import ml_analyzer.analysis.apk as analysis_apk


def test_androguard_method_to_jni_name():
    jni_name = analysis_apk.androguard_method_to_jni_name(
        'Lorg/tensorflow/lite/NativeInterpreterWrapper;', 'allocateTensors', '(J J)J')
    assert jni_name == 'Java_org_tensorflow_lite_NativeInterpreterWrapper_allocateTensors'
    jni_name = analysis_apk.androguard_method_to_jni_name(
        'Lpkg/Cls;', 'f', '(I Ljava/lang/String;)Z', overloaded=True)
    assert jni_name == 'Java_pkg_Cls_f__ILjava_lang_String_2'


def test_androguard_method_to_jimple():
    jimple_name = analysis_apk.androguard_method_to_jimple_name(
        'Lorg/tensorflow/lite/NativeInterpreterWrapper;', 'allocateTensors', '(J J)J')
    assert jimple_name == '<org.tensorflow.lite.NativeInterpreterWrapper: long allocateTensors(long,long)>'
    jimple_name = analysis_apk.androguard_method_to_jimple_name(
        'Landroid/widget/Toast;', 'makeText', '(Landroid/content/Context; Ljava/lang/CharSequence; I)Landroid/widget/Toast;')
    assert jimple_name == '<android.widget.Toast: android.widget.Toast makeText(android.content.Context,java.lang.CharSequence,int)>'
    jimple_name = analysis_apk.androguard_method_to_jimple_name('Lorg/tensorflow/lite/task/vision/detector/ObjectDetector;',
                                                                'initJniWithByteBuffer',
                                                                '(Ljava/nio/ByteBuffer; Lorg/tensorflow/lite/task/vision/detector/ObjectDetector$ObjectDetectorOptions;)J')
    assert jimple_name == '<org.tensorflow.lite.task.vision.detector.ObjectDetector: long initJniWithByteBuffer(java.nio.ByteBuffer,org.tensorflow.lite.task.vision.detector.ObjectDetector$ObjectDetectorOptions)>'
