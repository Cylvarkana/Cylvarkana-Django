"""
!/usr/bin/env python3
-*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:        tasks.py
Purpose:     Create common tasks for maintaining, updating and other administrative Ambivis services
Author:      Kodama Chameleon <contact@kodamachameleon.com>
Created:     8/30/2024
Copyright:   (c) Kodama Chameleon 2024
License:     CC BY 4.0
-------------------------------------------------------------------------------
"""
from celery import shared_task
from .apps import logger

@shared_task
def prep_model(train: bool=True):
    """
    Pre-process manually rated CVEs
    """
    from .models import PreProcessedCVE, CVERating
    from .utils.hoot import pre_process_dataset

    # Start with a clean slate
    PreProcessedCVE.objects.all().delete()
    logger.warning(f"Deleted and rebuilding current pre-processed data...")

    # Remove any previously auto-rated CVERatings to force use of latest model
    CVERating.objects.filter(method='auto').delete()
    logger.warning(f"Deleted all CVERatings with method 'auto'")

    # Populate data
    pre_process_dataset()

    if train:
        # Trigger model training after dataset preparation
        train_model.delay()

    logger.info(f"Finished pre-processing manually ratec CVEs")


@shared_task
def train_model(train_percent: float=0.8, model_name: str="cve_model"):
    """
    Train a machine learning model on the pre-processed CVE data.
    """
    from .utils.hoot import extract_features_and_labels, train_and_save_model, split_data
    from .models import PreProcessedCVE

    preprocessed_data = PreProcessedCVE.objects.all()

    if preprocessed_data.exists():
        # Extract features and labels
        logger.debug("Extracting features from pre-processed data...")
        X, y = extract_features_and_labels(preprocessed_data)
        logger.debug("SUCCESS: Features extracted from pre-processed data.")

        # Split the data into training and testing sets
        logger.debug("Splitting extracted features into train and test...")
        X_train, X_test, y_train, y_test = split_data(X, y, train_percent=train_percent)
        logger.debug("SUCCESS: Extracted features split into X_train, X_test, y_train, y_test")

        # Train and save the model
        logger.info(f"Training {model_name} on {len(preprocessed_data)} manually rated CVEs...")
        model_path = train_and_save_model(X_train, y_train, X_test, y_test, model_name=model_name)

        results = f"Model trained and saved to {model_path}, predictions stored in CVERating."
        logger.info(results)

        return results
    else:
        e_msg = "No data to train the model."
        logger.error(e_msg)

        return e_msg

@shared_task
def predict_priority(cveId: str, model_name: str = "cve_model"):
    """
    Task to predict the priority of a CVE given its ID using a specified model.
    
    Args:
        cve_id (str): The ID of the CVE to predict.
        model_name (str): The name of the model to use for prediction.
    """
    from .utils.hoot import predict_cve
    from .utils.system import cve_lookup
    from .models import CVERating, CVE
    from core.models import Credential
    from core.utils.format import validate_cve

    # Input checking
    cveId = validate_cve(cveId)
    if not cveId:
        raise ValueError("Invalid CVE Format")

    # Fetch the CVE object using the provided cve_id
    try:
        cve = cve_lookup(cveId=cveId, nist_api_key=Credential.objects.get(cred_type="key", platform='nist').value)
    except CVE.DoesNotExist:
        logger.error(f"CVE with ID {cveId} does not exist.")
        return None

    cve_rating = CVERating.objects.filter(cve=cve).first()
    if not cve_rating:
        try:
            cve_rating = predict_cve(cve=cve, model_name=model_name)
            logger.info(f"BioTremor rated {cveId} as {cve_rating.priority}")
            return cve_rating
        except Exception as e:
            logger.error(f"Error predicting priority for CVE {cveId}: {e}")
            raise
    else:
        logger.info(f"{cveId} already has a rating of {cve_rating.priority}")

@shared_task
def backfill_weakness_cwe(weaknesses=None):
    """
    Backfill CWE foreign key for Weakness instances that are missing it.
    
    Parameters:
    -----------
    weaknesses : QuerySet, optional
        A queryset of Weakness instances to process. Defaults to all Weakness objects where cwe__isnull=True.
    """
    from .models import Weakness
    from .utils.system import cwe_lookup

    # Default to all Weakness instances missing a CWE foreign key if no queryset is provided
    if weaknesses is None:
        weaknesses = Weakness.objects.filter(cwe__isnull=True)

    # Loop through each weakness and attempt to backfill CWE foreign key
    for weakness in weaknesses:
        # Validate that the description is formatted correctly
        cwe_id = None
        if isinstance(weakness.description, str) and weakness.description.startswith('CWE-'):
            try:
                # Extract the CWE number from 'CWE-<number>'
                cwe_id = int(weakness.description.split('-')[1])
            except (IndexError, ValueError):
                logger.warning(f"Invalid CWE format for weakness: {weakness.description}")
                continue

        # Proceed to lookup the CWE instance if a valid CWE ID was extracted
        if cwe_id:
            try:
                cwe_instance = cwe_lookup(cwe_id)
                if cwe_instance:
                    # Update the Weakness instance with the CWE
                    weakness.cwe = cwe_instance
                    weakness.save()
                    logger.info(f"Updated Weakness {weakness.id} with CWE {cwe_instance.id}")
                else:
                    logger.info(f"No CWE found for ID: {cwe_id}")
            except Exception as e:
                logger.error(f"Error looking up or updating CWE for weakness {weakness.id}: {e}")
        else:
            logger.info(f"No valid CWE ID extracted for weakness {weakness.id} with description: {weakness.description}")
