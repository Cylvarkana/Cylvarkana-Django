"""
!/usr/bin/env python3
 -*- coding: utf-8 -*-
-------------------------------------------------------------------------------
Name:       hoot
Purpose:    Machine Learning tasks for the BioTremor app
Author:     Kodama Chameleon <contact@kodamachameleon.com>
Created:    08/14/2024
-------------------------------------------------------------------------------
"""
import os
import joblib
import numpy as np

from django.db.models import Avg, Count
from django.conf import settings

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

from biotremor.models import (
    CVE,
    CVSSMetricV31,
    CVSSMetricV20,
    EPSS,
    CWE,
    Weakness,
    CVERating,
    PreProcessedCVE,
    Reference,
    Priority,
    models
)
from biotremor.apps import logger, app_name

MODELS_DIR = 'data'

class RubberSnake:
    """
    Return dummy values for missing data
    """

    def __init__(self, manual_cve_ids: models.QuerySet) -> None:
        """
        Initialize the RubberDuck instance to use 'manual' CVE records as a reference.
        """
        self.manual_cve_ids = manual_cve_ids

    def get_most_common_fields(self, model, categorical_fields, filter_field=None):
        """
        Returns the most common values for the given categorical fields from the specified model.

        Args:
            - model: The model class to query from.
            - categorical_fields: List of categorical fields (strings) to find the most common values.
            - filter_field: Optional filter to apply to limit the query scope (e.g., 'cve__id__in').

        Returns:
            - dict: A dictionary where the keys are field names and the values are the most common values.
        """
        most_common = {}

        # Dynamically filter the queryset if filter_field is provided
        queryset = model.objects.filter(**filter_field) if filter_field else model.objects.all()

        # Loop through each field and calculate the most common value
        for field in categorical_fields:
            most_common_value = (
                queryset
                .values(field)
                .annotate(count=Count(field))
                .order_by('-count')
                .first()
            )
            most_common[field] = most_common_value[field] if most_common_value else 'N/A'

        return most_common

    def dummy_CVSSMetricV31(self, cve: CVE):
        """
        Define placeholders for CVSS 3.1 using the most common values for categorical fields
        and the average values for numerical fields.
        """

        # Define categorical fields for CVSS 3.1 metrics
        categorical_fields = [
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'scope', 'confidentiality_impact',
            'integrity_impact', 'availability_impact'
        ]

        # Get most common values for categorical fields
        most_common = self.get_most_common_fields(CVSSMetricV31, categorical_fields, filter_field={'cve__in': self.manual_cve_ids})

        # Get average values for numerical fields from 'manual' CVEs
        avg_values = self.manual_cve_ids.aggregate(
            avg_base_score=Avg('cvss_metrics_v3__base_score'),
            avg_exploitability_score=Avg('cvss_metrics_v3__exploitability_score'),
            avg_impact_score=Avg('cvss_metrics_v3__impact_score')
        )

        # Construct a dummy CVSSMetricV31 instance with computed values
        cvss_metric_v3 = CVSSMetricV31(
            cve=cve,
            base_score=round(avg_values.get('avg_base_score', 0.0), 2),
            exploitability_score=round(avg_values.get('avg_exploitability_score', 0.0), 2),
            impact_score=round(avg_values.get('avg_impact_score', 0.0), 2),
            attack_vector=most_common.get('attack_vector', 'N/A'),
            attack_complexity=most_common.get('attack_complexity', 'N/A'),
            privileges_required=most_common.get('privileges_required', 'N/A'),
            user_interaction=most_common.get('user_interaction', 'N/A'),
            scope=most_common.get('scope', 'N/A'),
            confidentiality_impact=most_common.get('confidentiality_impact', 'N/A'),
            integrity_impact=most_common.get('integrity_impact', 'N/A'),
            availability_impact=most_common.get('availability_impact', 'N/A')
        )

        return cvss_metric_v3
    
    def dummy_CVSSMetricV20(self, cve: CVE):
        """
        Define placeholders for CVSS 2.0 using the most common categorical values 
        and average values for numerical fields.
        """

        # Define categorical fields for CVSS 2.0 metrics
        categorical_fields = [
            'access_vector', 'access_complexity', 'authentication',
            'confidentiality_impact', 'integrity_impact', 'availability_impact'
        ]

        # Get most common values for categorical fields from CVSSMetricV20
        most_common = self.get_most_common_fields(CVSSMetricV20, categorical_fields, filter_field={'cve__in': self.manual_cve_ids})

        # Get average values for numerical fields from 'manual' CVEs
        avg_values = self.manual_cve_ids.aggregate(
            avg_base_score=Avg('cvss_metrics_v2__base_score'),
            avg_exploitability_score=Avg('cvss_metrics_v2__exploitability_score'),
            avg_impact_score=Avg('cvss_metrics_v2__impact_score')
        )

        # Construct a dummy CVSSMetricV20 instance with the computed values
        cvss_metric_v2 = CVSSMetricV20(
            cve=cve,
            base_score=round(avg_values.get('avg_base_score', 0.0), 2),
            exploitability_score=round(avg_values.get('avg_exploitability_score', 0.0), 2),
            impact_score=round(avg_values.get('avg_impact_score', 0.0), 2),
            access_vector=most_common.get('access_vector', 'N/A'),
            access_complexity=most_common.get('access_complexity', 'N/A'),
            authentication=most_common.get('authentication', 'N/A'),
            confidentiality_impact=most_common.get('confidentiality_impact', 'N/A'),
            integrity_impact=most_common.get('integrity_impact', 'N/A'),
            availability_impact=most_common.get('availability_impact', 'N/A')
        )

        return cvss_metric_v2

    def dummy_epss(self, cve: CVE):
        """
        Define placeholder values for EPSS using the average values for score and percentile.
        """

        # Calculate the average values for 'score' and 'percentile' from 'manual' CVEs
        avg_values = self.manual_cve_ids.aggregate(
            avg_score=Avg('epss__score'),
            avg_percentile=Avg('epss__percentile')
        )

        # Create a dummy EPSS instance with the computed average values
        epss_metric = EPSS(
            cve=cve,
            score=round(avg_values.get('avg_score', 0.0), 2),
            percentile=round(avg_values.get('avg_percentile', 0.0), 2)
        )

        return epss_metric

    def dummy_weakness(self, cve: CVE):
        """
        Define placeholder values for Weakness
        """
        cwe = CWE(
            id='UNKNOWN',
            name='N/A',
            status='N/A',
            description='N/A',
            cwe_type = 'weakness'
        )

        # Fetch Weakness or create a temporary instance
        self.weakness = Weakness(
            cve=cve,
            cwe=cwe
        )

        return self.weakness


def build_label_encoder(model: models.Model, feature: str, related_model_field: str='cve') -> LabelEncoder:
    """
    Create a label encoder for a given model.feature, filtered by manually rated CVEs.
    
    Args:
    - model: The model to retrieve data from (e.g., CVSSMetricV31).
    - feature: The feature (field) to encode (e.g., 'attack_vector').
    - related_model_field: The field that relates this model to CVE (default: 'cve').

    Returns:
    - LabelEncoder: Fitted label encoder for the specified feature.
    """
    # Get the manually rated CVEs
    manual_cve_ids = CVERating.objects.filter(method='manual').values_list('cve_id', flat=True)

    # Determine if the feature is a foreign key (e.g., cwe.id)
    if '.' in feature:
        related_field, sub_field = feature.split('.')
        # Access the related foreign key field (e.g., cwe.id)
        unique_values = model.objects.filter(**{related_model_field + '__in': manual_cve_ids})
        unique_values = unique_values.values_list(f"{related_field}__{sub_field}", flat=True).distinct()
    else:
        # Handle regular fields
        unique_values = model.objects.filter(**{related_model_field + '__in': manual_cve_ids})
        unique_values = unique_values.values_list(feature, flat=True).distinct()

    # Append UNKNOWN as default label for missing values
    unique_values = list(unique_values)
    if "UNKNOWN" not in unique_values:
        unique_values.append("UNKNOWN")

    # Fit the LabelEncoder
    logger.debug(f"Encoding {feature} with values {', '.join(map(str, unique_values))}")
    encoder = LabelEncoder()
    encoder.fit(unique_values)

    return encoder

def pre_process_dataset():
    """
    Pre process manually rated CVEs for training data
    """
    # Create encoders
    encoders = {
        "CVSSMetricV31.attack_vector": CVSSMetricV31,
        "CVSSMetricV31.attack_complexity":CVSSMetricV31,
        "CVSSMetricV31.privileges_required": CVSSMetricV31,
        "CVSSMetricV31.user_interaction": CVSSMetricV31,
        "CVSSMetricV31.scope": CVSSMetricV31,
        "CVSSMetricV31.confidentiality_impact": CVSSMetricV31,
        "CVSSMetricV31.integrity_impact": CVSSMetricV31,
        "CVSSMetricV31.availability_impact": CVSSMetricV31,
        "CVSSMetricV20.access_vector": CVSSMetricV20,
        "CVSSMetricV20.access_complexity": CVSSMetricV20,
        "CVSSMetricV20.authentication": CVSSMetricV20,
        "CVSSMetricV20.confidentiality_impact": CVSSMetricV20,
        "CVSSMetricV20.integrity_impact": CVSSMetricV20,
        "CVSSMetricV20.availability_impact": CVSSMetricV20,
        "Weakness.cwe.id": Weakness,
    }
    for encoder, model in encoders.items():
        encoders[encoder] = build_label_encoder(model, encoder.split('.')[-1])
    
    manually_rated_cves = CVE.objects.filter(cverating__method='manual')
    logger.info(f"Found {len(manually_rated_cves)} manually rated CVEs for training, testing, and validation")
    
    # Build the dataset
    placeholders = RubberSnake(manually_rated_cves)
    for cve in manually_rated_cves:
        
        # Only process if does not already exist
        pre_processed_cve = PreProcessedCVE.objects.filter(cve=cve).first()
        if not pre_processed_cve:
            preprocessed_data = pre_process_cve(cve, encoders, placeholders)
            if preprocessed_data:
                create_preprocessed_cve_instance(cve, preprocessed_data)

def pre_process_cve(cve: CVE, encoders: dict, placeholders: RubberSnake) -> dict:
    """
    Pre-process the given CVE for training or making a prediction.
    
    Args:
    - cve_id (str): The ID of the CVE to be preprocessed for prediction.

    Returns:
    - dict: Preprocessed features ready for the ML model to predict on.
    """
    try:

        # Fetch cve related model instances (or use dummy values)
        cvss_metric_v3 = CVSSMetricV31.objects.filter(cve=cve).first()
        if not cvss_metric_v3:
            cvss_metric_v3 = placeholders.dummy_CVSSMetricV31(cve)
            logger.warning(f"No CVSS 3.1 for {cve.id}. Using dummy values: base_score={cvss_metric_v3.base_score}")

        cvss_metric_v2 = CVSSMetricV20.objects.filter(cve=cve).first()
        if not cvss_metric_v2:
            cvss_metric_v2 = placeholders.dummy_CVSSMetricV20(cve)
            logger.warning(f"No CVSS 2.0 for {cve.id}. Using dummy values: base_score={cvss_metric_v2.base_score}")

        epss_metric = EPSS.objects.filter(cve=cve).first()
        if not epss_metric:
            epss_metric = placeholders.dummy_epss(cve)
            logger.warning(f"No EPSS for {cve.id}. Using dummy values: score={epss_metric.score}, percentile={epss_metric.percentile}")

        weakness = Weakness.objects.filter(cve=cve).first()
        if not weakness or not weakness.cwe:
            weakness = placeholders.dummy_weakness(cve)
            logger.warning(f"No Weakness for {cve.id}. Using dummy values: cwe.id=UNKNOWN")

        # Encode CISA exploit add (binary 0 or 1)
        cisa_exploit_add_encoded = 1 if cve.cisa_exploit_add else 0
        
        # One-hot encode Reference.tags
        references = Reference.objects.filter(cve=cve)
        has_patch = 0
        has_mitigation = 0
        has_us_gov_resource = 0
        has_press_media_coverage = 0
        has_exploit = 0
        
        for reference in references:
            tags = [tag.strip().lower() for tag in reference.tags.split(',')]
            if 'patch' in tags:
                has_patch = 1
            if 'mitigation' in tags:
                has_mitigation = 1
            if 'us government resource' in tags:
                has_us_gov_resource = 1
            if 'press/media coverage' in tags:
                has_press_media_coverage = 1
            if 'exploit' in tags:
                has_exploit = 1

        # --- Create preprocessed features for prediction ---
        preprocessed_data = {
            'CVSSMetricV31.base_score': cvss_metric_v3.base_score,
            'CVSSMetricV31.exploitability_score': cvss_metric_v3.exploitability_score,
            'CVSSMetricV31.impact_score': cvss_metric_v3.impact_score,
            'CVSSMetricV20.base_score': cvss_metric_v2.base_score,
            'CVSSMetricV20.exploitability_score': cvss_metric_v2.exploitability_score,
            'CVSSMetricV20.impact_score': cvss_metric_v2.impact_score,
            'EPSS.score': epss_metric.score,
            'EPSS.percentile': epss_metric.percentile,
            'CVE.cisa_exploit_add': cisa_exploit_add_encoded,

             # Add one-hot encoded reference tags
            'Reference.has_patch': has_patch,
            'Reference.has_mitigation': has_mitigation,
            'Reference.has_us_gov_resource': has_us_gov_resource,
            'Reference.has_press_media_coverage': has_press_media_coverage,
            'Reference.has_exploit': has_exploit,
        }

        # Add encoded values
        encoded_values = {
            "CVSSMetricV31.attack_vector": cvss_metric_v3.attack_vector,
            "CVSSMetricV31.attack_complexity": cvss_metric_v3.attack_complexity,
            "CVSSMetricV31.privileges_required": cvss_metric_v3.privileges_required,
            "CVSSMetricV31.user_interaction": cvss_metric_v3.user_interaction,
            "CVSSMetricV31.scope": cvss_metric_v3.scope,
            "CVSSMetricV31.confidentiality_impact": cvss_metric_v3.confidentiality_impact,
            "CVSSMetricV31.integrity_impact": cvss_metric_v3.integrity_impact,
            "CVSSMetricV31.availability_impact": cvss_metric_v3.availability_impact,
            "CVSSMetricV20.access_vector": cvss_metric_v2.access_vector,
            "CVSSMetricV20.access_complexity": cvss_metric_v2.access_complexity,
            "CVSSMetricV20.authentication": cvss_metric_v2.authentication,
            "CVSSMetricV20.confidentiality_impact": cvss_metric_v2.confidentiality_impact,
            "CVSSMetricV20.integrity_impact": cvss_metric_v2.integrity_impact,
            "CVSSMetricV20.availability_impact": cvss_metric_v2.availability_impact,
            "Weakness.cwe.id": weakness.cwe.id if weakness.cwe else "UNKNOWN",
        }
        for feature, value in encoded_values.items():
            preprocessed_data[f"{feature}_encoded"] = encoders[feature].transform([value])[0]

        return preprocessed_data

    except Exception as e:
        logger.error(f"Error encoding {cve.id}: {e}")
        return None

def create_preprocessed_cve_instance(cve, preprocessed_data, store_instance: bool=True):
    """
    Create a PreProcessedCVE instance from the preprocessed data.

    Args:
    - cve: The CVE instance.
    - preprocessed_data: The dictionary of preprocessed values to store.
    - store_instance: Flag indicating whether to save the instance to the database or not.

    Returns:
    - A PreProcessedCVE instance (stored or unstored).
    """

    # Common preprocessed data for the CVE
    preprocessed_fields = {
        # CVSS 3.1
        "cvss_v31_base_score": preprocessed_data['CVSSMetricV31.base_score'],
        "cvss_v31_exploitability_score": preprocessed_data['CVSSMetricV31.exploitability_score'],
        "cvss_v31_impact_score": preprocessed_data['CVSSMetricV31.impact_score'],
        "cvss_v31_attack_vector_encoded": preprocessed_data['CVSSMetricV31.attack_vector_encoded'],
        "cvss_v31_attack_complexity_encoded": preprocessed_data['CVSSMetricV31.attack_complexity_encoded'],
        "cvss_v31_privileges_required_encoded": preprocessed_data['CVSSMetricV31.privileges_required_encoded'],
        "cvss_v31_user_interaction_encoded": preprocessed_data['CVSSMetricV31.user_interaction_encoded'],
        "cvss_v31_scope_encoded": preprocessed_data['CVSSMetricV31.scope_encoded'],
        "cvss_v31_confidentiality_impact_encoded": preprocessed_data['CVSSMetricV31.confidentiality_impact_encoded'],
        "cvss_v31_integrity_impact_encoded": preprocessed_data['CVSSMetricV31.integrity_impact_encoded'],
        "cvss_v31_availability_impact_encoded": preprocessed_data['CVSSMetricV31.availability_impact_encoded'],

        # CVSS 2.0
        "cvss_v20_base_score": preprocessed_data['CVSSMetricV20.base_score'],
        "cvss_v20_exploitability_score": preprocessed_data['CVSSMetricV20.exploitability_score'],
        "cvss_v20_impact_score": preprocessed_data['CVSSMetricV20.impact_score'],
        "cvss_v20_access_vector_encoded": preprocessed_data['CVSSMetricV20.access_vector_encoded'],
        "cvss_v20_access_complexity_encoded": preprocessed_data['CVSSMetricV20.access_complexity_encoded'],
        "cvss_v20_authentication_encoded": preprocessed_data['CVSSMetricV20.authentication_encoded'],
        "cvss_v20_confidentiality_impact_encoded": preprocessed_data['CVSSMetricV20.confidentiality_impact_encoded'],
        "cvss_v20_integrity_impact_encoded": preprocessed_data['CVSSMetricV20.integrity_impact_encoded'],
        "cvss_v20_availability_impact_encoded": preprocessed_data['CVSSMetricV20.availability_impact_encoded'],

        # EPSS
        "epss_score": preprocessed_data['EPSS.score'],
        "epss_percentile": preprocessed_data['EPSS.percentile'],

        # CVE-specific fields
        "cisa_exploit_add": preprocessed_data['CVE.cisa_exploit_add'],
        "weakness_cwe_encoded": preprocessed_data['Weakness.cwe.id_encoded'],
        "cve_published_epoch": int(cve.published.timestamp()),

        # Reference tags
        "has_patch": preprocessed_data['Reference.has_patch'],
        "has_mitigation": preprocessed_data['Reference.has_mitigation'],
        "has_us_gov_resource": preprocessed_data['Reference.has_us_gov_resource'],
        "has_press_media_coverage": preprocessed_data['Reference.has_press_media_coverage'],
        "has_exploit": preprocessed_data['Reference.has_exploit']
    }

    # Set rating depending on whether we are storing the instance or not
    preprocessed_fields["rating"] = cve.cverating.priority if store_instance else None

    # Create a PreProcessedCVE instance
    pre_processed_cve = PreProcessedCVE(cve=cve, **preprocessed_fields)

    # Save the instance to the database if needed
    if store_instance:
        pre_processed_cve.save()
        logger.info(f"Created and saved pre-processed instance of {cve.id}")
    else:
        logger.info(f"Created pre-processed instance of {cve.id} (not saved)")

    return pre_processed_cve


def split_data(X, y, train_percent=0.8):
    """
    Split the data into training and testing sets.
    
    Parameters:
    - X: Feature matrix (NumPy array)
    - y: Labels (NumPy array)
    - train_percent: Float between 0 and 1 indicating the proportion of data to use for training
    
    Returns:
    - X_train, X_test, y_train, y_test: Split datasets
    """
    return train_test_split(X, y, train_size=train_percent, random_state=42)


def extract_features_and_labels(data, predict: bool=False):
    """
    Extract features and labels from the PreProcessedCVE queryset.
    
    Args:
    - data (QuerySet): The dataset to extract features from.

    Returns:
    - X (np.array): Feature matrix.
    - y (np.array): Labels (CVE Ratings).
    """
    # Extract the features
    features = []
    labels = []

    for item in data:
        features.append([
            item.cvss_v31_base_score,
            item.cvss_v31_exploitability_score,
            item.cvss_v31_impact_score,
            item.cvss_v31_attack_vector_encoded,
            item.cvss_v31_attack_complexity_encoded,
            item.cvss_v31_privileges_required_encoded,
            item.cvss_v31_user_interaction_encoded,
            item.cvss_v31_scope_encoded,
            item.cvss_v31_confidentiality_impact_encoded,
            item.cvss_v31_integrity_impact_encoded,
            item.cvss_v31_availability_impact_encoded,
            item.cvss_v20_base_score,
            item.cvss_v20_exploitability_score,
            item.cvss_v20_impact_score,
            item.cvss_v20_access_vector_encoded,
            item.cvss_v20_access_complexity_encoded,
            item.cvss_v20_authentication_encoded,
            item.cvss_v20_confidentiality_impact_encoded,
            item.cvss_v20_integrity_impact_encoded,
            item.cvss_v20_availability_impact_encoded,
            item.epss_score,
            item.epss_percentile,
            item.cisa_exploit_add,
            item.weakness_cwe_encoded,
        ])

        # Extract the rating (label)
        if predict:
            labels.append(None)
        else:
            labels.append(item.rating.id)

    # Convert to NumPy arrays
    X = np.array(features)
    y = np.array(labels)

    return X, y


def predict_cve_rating(cve, model_name: str="cve_model"):
    """
    Predict the CVE rating using the trained model.
    """
    model_path = os.path.join(settings.BASE_DIR, app_name, MODELS_DIR, f'{model_name}.joblib')

    # Load the trained model
    model = joblib.load(model_path)

    # Create the feature vector from the CVE data
    feature_vector = np.array([
        cve.cvss_v31_base_score,
        cve.cvss_v31_exploitability_score,
        cve.cvss_v31_impact_score,
        cve.cvss_v31_attack_vector_encoded,
        cve.cvss_v31_attack_complexity_encoded,
        cve.cvss_v31_privileges_required_encoded,
        cve.cvss_v31_user_interaction_encoded,
        cve.cvss_v31_scope_encoded,
        cve.cvss_v31_confidentiality_impact_encoded,
        cve.cvss_v31_integrity_impact_encoded,
        cve.cvss_v31_availability_impact_encoded,
        cve.cvss_v20_base_score,
        cve.cvss_v20_exploitability_score,
        cve.cvss_v20_impact_score,
        cve.cvss_v20_access_vector_encoded,
        cve.cvss_v20_access_complexity_encoded,
        cve.cvss_v20_authentication_encoded,
        cve.cvss_v20_confidentiality_impact_encoded,
        cve.cvss_v20_integrity_impact_encoded,
        cve.cvss_v20_availability_impact_encoded,
        cve.epss_score,
        cve.epss_percentile,
        cve.cisa_exploit_add,
        cve.weakness_cwe_encoded,
    ]).reshape(1, -1)

    # Make a prediction
    predicted_rating = model.predict(feature_vector)[0]

    return predicted_rating


def train_and_save_model(
        X_train,
        y_train,
        X_test,
        y_test,
        save_model: bool=True,
        model_name: str="cve_model_gb"
    ):
    """
    Train a machine learning model using GradientBoostingClassifier and save it to disk.
    
    Parameters:
    - X_train: Training feature matrix
    - y_train: Training labels
    - X_test: Testing feature matrix
    - y_test: Testing labels
    - save_model: Boolean to indicate whether to save the model
    - model_name: The name to save the model under
    
    Returns:
    - model: Trained model object
    - model_path: Path to the saved model
    """

    # Initialize and train the Gradient Boosting model
    model = GradientBoostingClassifier(random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"Gradient Boosting Model accuracy on test set: {accuracy:.2f}")

    # Save the trained model to a file
    if save_model:
        model_path = os.path.join(settings.BASE_DIR, app_name, MODELS_DIR, f'{model_name}.joblib')
        joblib.dump(model, model_path)

    return model, model_path


def load_model(model_name: str="cve_model"):
    """
    Load a previously trained model.
    """
    model_path = os.path.join(settings.BASE_DIR, app_name, MODELS_DIR, f'{model_name}.joblib')

    return joblib.load(model_path)


def predict_cve(cve: CVE, model_name: str = "cve_model"):
    """
    Predict a CVE priority given an ID.
    
    Args:
        cve_id (str): The ID of the CVE to predict.
        model_name (str): The name of the model to use for prediction.
    
    Returns:
        predicted_rating: The predicted rating for the CVE.
    """

    # Create encoders for the CVSS metrics and weaknesses
    encoders = {
        "CVSSMetricV31.attack_vector": CVSSMetricV31,
        "CVSSMetricV31.attack_complexity": CVSSMetricV31,
        "CVSSMetricV31.privileges_required": CVSSMetricV31,
        "CVSSMetricV31.user_interaction": CVSSMetricV31,
        "CVSSMetricV31.scope": CVSSMetricV31,
        "CVSSMetricV31.confidentiality_impact": CVSSMetricV31,
        "CVSSMetricV31.integrity_impact": CVSSMetricV31,
        "CVSSMetricV31.availability_impact": CVSSMetricV31,
        "CVSSMetricV20.access_vector": CVSSMetricV20,
        "CVSSMetricV20.access_complexity": CVSSMetricV20,
        "CVSSMetricV20.authentication": CVSSMetricV20,
        "CVSSMetricV20.confidentiality_impact": CVSSMetricV20,
        "CVSSMetricV20.integrity_impact": CVSSMetricV20,
        "CVSSMetricV20.availability_impact": CVSSMetricV20,
        "Weakness.cwe.id": Weakness,
    }

    for encoder, model in encoders.items():
        encoders[encoder] = build_label_encoder(model, encoder.split('.')[-1])

    # Fetch manually rated CVEs for training and validation
    manually_rated_cves = CVE.objects.filter(cverating__method='manual')
    logger.info(f"Found {len(manually_rated_cves)} manually rated CVEs for training, testing, and validation.")

    # Preprocess the CVE data
    placeholders = RubberSnake(manually_rated_cves)

    preprocessed_data = pre_process_cve(cve, encoders, placeholders)

    if preprocessed_data:
        cve_processed = create_preprocessed_cve_instance(cve, preprocessed_data, store_instance=False)

        # Generate predictions
        predicted_rating = predict_cve_rating(cve_processed, model_name=model_name)

        # Create and save a new CVERating instance
        rating = CVERating.objects.create(
            cve=cve,
            priority=Priority.objects.get(id=int(predicted_rating)),
            method='auto',
            source='BioTremor'
        )

        return rating
    else:
        logger.error(f"Preprocessed data for CVE {cve.id} is not valid.")
        return None
