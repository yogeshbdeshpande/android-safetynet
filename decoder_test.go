package safetynet

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yogeshbdeshpande/android-safetynet"
)

var safetynetJws = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGYmpDQ0JGYWdBd0lCQWdJUUFhM09LT2RvVFk0UUFBQUFBQTNYWERBTkJna3Foa2lHOXcwQkFRc0ZBREJHTVFzd0NRWURWUVFHRXdKVlV6RWlNQ0FHQTFVRUNoTVpSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6SUV4TVF6RVRNQkVHQTFVRUF4TUtSMVJUSUVOQklERkVOREFlRncweU1qQXpNakF5TVRFMU1qRmFGdzB5TWpBMk1UZ3lNVEUxTWpCYU1CMHhHekFaQmdOVkJBTVRFbUYwZEdWemRDNWhibVJ5YjJsa0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMbXFMQlhWNENaQTVzVDVjVGZ1WGN3MTFXRDJZVVczZUFKdmRxK1hJYkhEZ01OTUJyc3gvWER4NkxtOU9tSkNVNHZDcFdJTjRXQ0gyMFQ5T2ZlNkhkeU52RWVpM3pobHpOMFovWVR5b1RlcFdwNUgvbXJuR29zU3NtcEp1NDV3OVJYbm5KbElrRzU5dDN0V1JoYXNZZW5GY0hlY0ZobG1odm5UQnRHa01Vb0VGREZnanltZ2twUUdkMmxoaU9YWGJwMzE1SXlGbEdUVFpvNERBYTZiMHp2VGZQOXV6R1FJZHhma3N5TUlGZmJDYVd6TjNPanB1bVIwMHg2SVZjZDdyOUxvOVBlVWw5a296cjhFaDRDWS9PQitEOVEvVjZ4RVpiVHNHeXc0aUFxQ0tvMTRDRXpDRVFIMEZWWTQ1cFg3b2IrbWhmL1pKbWNzL014blZGbkx6bDBDQXdFQUFhT0NBbjh3Z2dKN01BNEdBMVVkRHdFQi93UUVBd0lGb0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFUQU1CZ05WSFJNQkFmOEVBakFBTUIwR0ExVWREZ1FXQkJUOVI3Z21PZUQxdlpRVkNIYzBUdGh2T1lpMzlEQWZCZ05WSFNNRUdEQVdnQlFsNGhnT3NsZVJsQ3JsMUYyR2tJUGVVN080a2pCN0JnZ3JCZ0VGQlFjQkFRUnZNRzB3T0FZSUt3WUJCUVVITUFHR0xHaDBkSEE2THk5dlkzTndMbkJyYVM1bmIyOW5MM012WjNSek1XUTBhVzUwTDNoT0xWOHdkRE4zV1Rrd01ERUdDQ3NHQVFVRkJ6QUNoaVZvZEhSd09pOHZjR3RwTG1kdmIyY3ZjbVZ3Ynk5alpYSjBjeTluZEhNeFpEUXVaR1Z5TUIwR0ExVWRFUVFXTUJTQ0VtRjBkR1Z6ZEM1aGJtUnliMmxrTG1OdmJUQWhCZ05WSFNBRUdqQVlNQWdHQm1lQkRBRUNBVEFNQmdvckJnRUVBZFo1QWdVRE1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEE2THk5amNteHpMbkJyYVM1bmIyOW5MMmQwY3pGa05HbHVkQzlZTWtveVNISmZOMUJwVFM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWRnQlJvN0QxL1FGNW5GWnR1RGQ0and5a2Vzd2JKOHYzbm9oQ21nMysxSXNGNVFBQUFYK3Baa0pyQUFBRUF3QkhNRVVDSVFDb2RWRnpPQ1VubHVRUzB0MG9HdUEzdlZFR0Zxb2I4SVJiQ3BZeTdVZmNBUUlnRi9NZVVSdG9EN1FraFhCTjB1cmlDdEwvTENsMW1zRE5oWjFtMUhKeEpRb0FkZ0FwZWI3d25qazVJZkJXYzU5anBYZmx2bGQ5bkdBSytQbE5YU1pjSlYzSGhBQUFBWCtwWmtKWUFBQUVBd0JITUVVQ0lRQ1pvRW1Bbzc0UitGT0pQeVJLYkkyRSs2S0NYNkF1WG1oZnNXa2h0aUFLYWdJZ1p1dmZIcUE2UE9sM0JkV3RlU1l4TzA2QmNwT3dUYTV6NjVqSkw0dExEckl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQURJcC93blFsZnE3dVZ6dDU3MHlRRTJOQVA1ajh5OGFzWWhKTXcrUTBYZ3M2a3pqZnpGL2g3OVpmRlhLOTh3QVJhVnI2amVSQXo2Y3E4cUVIMU8yQkQ5eDVEQ09UZzJxclNnSldiTU5VWkR5TXV6RmVyQ2EyNzloQklQVXBqNzg0YUdsYWp4Y2M3VHRYSHpacnhmbGM0d1BzZ2JnQ2twd3VqNmowandDNjdRNGJrOVVYKzNxcGw3MmFKMnpWbzFmT2s3U0ZwSTU4RjNJL1c4bkkva2Nwb1BvcDJCNkoxR3RxTURIRnByc3RnZUpMbFkzQWVmZWoyeW9Fd3UyajIrYzEvSjZ3SDV4YWRES3hnM052aDIreGhaUkZab0FUYjJlNllzeDRSMEJ0eWVYNEhaTWc0OFFhQk40N2xBeEFjZzR1YVNqRy8vQkhXTjM0cE1FYWNJeEdOMD0iLCJNSUlGakRDQ0EzU2dBd0lCQWdJTkFnQ09zZ0l6Tm1XTFpNM2JtekFOQmdrcWhraUc5dzBCQVFzRkFEQkhNUXN3Q1FZRFZRUUdFd0pWVXpFaU1DQUdBMVVFQ2hNWlIyOXZaMnhsSUZSeWRYTjBJRk5sY25acFkyVnpJRXhNUXpFVU1CSUdBMVVFQXhNTFIxUlRJRkp2YjNRZ1VqRXdIaGNOTWpBd09ERXpNREF3TURReVdoY05NamN3T1RNd01EQXdNRFF5V2pCR01Rc3dDUVlEVlFRR0V3SlZVekVpTUNBR0ExVUVDaE1aUjI5dloyeGxJRlJ5ZFhOMElGTmxjblpwWTJWeklFeE1RekVUTUJFR0ExVUVBeE1LUjFSVElFTkJJREZFTkRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBS3ZBcXFQQ0UyN2wwdzl6QzhkVFBJRTg5YkEreFRtRGFHN3k3VmZRNGMrbU9XaGxVZWJVUXBLMHl2MnI2NzhSSkV4SzBIV0RqZXErbkxJSE4xRW01ajZyQVJaaXhteVJTamhJUjBLT1FQR0JNVWxkc2F6dElJSjdPMGcvODJxai92R0RsLy8zdDR0VHF4aVJoTFFuVExYSmRlQisyRGhrZFU2SUlneDZ3TjdFNU5jVUgzUmNzZWpjcWo4cDVTajE5dkJtNmkxRmhxTEd5bWhNRnJvV1ZVR08zeHRJSDkxZHNneTRlRktjZktWTFdLM28yMTkwUTBMbS9TaUttTGJSSjVBdTR5MWV1RkptMkpNOWVCODRGa3FhM2l2clhXVWVWdHllMENRZEt2c1kyRmthenZ4dHh2dXNMSnpMV1lIazU1emNSQWFjREEyU2VFdEJiUWZEMXFzQ0F3RUFBYU9DQVhZd2dnRnlNQTRHQTFVZER3RUIvd1FFQXdJQmhqQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVUplSVlEckpYa1pRcTVkUmRocENEM2xPenVKSXdId1lEVlIwakJCZ3dGb0FVNUs4ckpuRWFLMGduaFM5U1ppenY4SWtUY1Q0d2FBWUlLd1lCQlFVSEFRRUVYREJhTUNZR0NDc0dBUVVGQnpBQmhocG9kSFJ3T2k4dmIyTnpjQzV3YTJrdVoyOXZaeTluZEhOeU1UQXdCZ2dyQmdFRkJRY3dBb1lrYUhSMGNEb3ZMM0JyYVM1bmIyOW5MM0psY0c4dlkyVnlkSE12WjNSemNqRXVaR1Z5TURRR0ExVWRId1F0TUNzd0thQW5vQ1dHSTJoMGRIQTZMeTlqY213dWNHdHBMbWR2YjJjdlozUnpjakV2WjNSemNqRXVZM0pzTUUwR0ExVWRJQVJHTUVRd0NBWUdaNEVNQVFJQk1EZ0dDaXNHQVFRQjFua0NCUU13S2pBb0JnZ3JCZ0VGQlFjQ0FSWWNhSFIwY0hNNkx5OXdhMmt1WjI5dlp5OXlaWEJ2YzJsMGIzSjVMekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBSVZUb3kyNGp3WFVyMHJBUGM5MjR2dVNWYktRdVl3M25MZmxMZkxoNUFZV0VlVmwvRHUxOFFBV1VNZGNKNm8vcUZaYmhYa0JIMFBOY3c5N3RoYWYyQmVvRFlZOUNrL2IrVUdsdWh4MDZ6ZDRFQmY3SDlQODRubnJ3cFIrNEdCRFpLK1hoM0kwdHFKeTJyZ09xTkRmbHI1SU1ROFpUV0EzeWx0YWt6U0JLWjZYcEYwUHBxeUNSdnAvTkNHdjJLWDJUdVBDSnZzY3AxL20ycFZUdHlCallQUlErUXVDUUdBSktqdE43UjVERnJmVHFNV3ZZZ1ZscENKQmt3bHU3KzdLWTNjVElmekU3Y21BTHNrTUtOTHVEeitSekNjc1lUc1ZhVTdWcDN4TDYwT1locUZrdUFPT3hEWjZwSE9qOStPSm1ZZ1BtT1Q0WDMrN0w1MWZYSnlSSDlLZkxSUDZuVDMxRDVubXNHQU9nWjI2LzhUOWhzQlcxdW85anU1ZlpMWlhWVlM1SDBIeUlCTUVLeUdNSVBoRldybHQvaEZTMjhOMXphS0kwWkJHRDNnWWdETGJpRFQ5ZkdYc3RwaytGbWM0b2xWbFdQelhlODF2ZG9FbkZicjVNMjcySGRnSldvK1doVDlCWU0wSmkrd2RWbW5SZmZYZ2xvRW9sdVROY1d6YzQxZEZwZ0p1OGZGM0xHMGdsMmliU1lpQ2k5YTZodlUwVHBwakp5SVdYaGtKVGNNSmxQcld4MVZ5dEVVR3JYMmwwSkR3UmpXLzY1NnIwS1ZCMDJ4SFJLdm0yWktJMDNUZ2xMSXBtVkNLM2tCS2tLTnBCTmtGdDhyaGFmY0NLT2I5SngvOXRwTkZsUVRsN0IzOXJKbEpXa1IxN1FuWnFWcHRGZVBGT1JvWm1Gek09IiwiTUlJRllqQ0NCRXFnQXdJQkFnSVFkNzBOYk5zMitScnFJUS9FOEZqVERUQU5CZ2txaGtpRzl3MEJBUXNGQURCWE1Rc3dDUVlEVlFRR0V3SkNSVEVaTUJjR0ExVUVDaE1RUjJ4dlltRnNVMmxuYmlCdWRpMXpZVEVRTUE0R0ExVUVDeE1IVW05dmRDQkRRVEViTUJrR0ExVUVBeE1TUjJ4dlltRnNVMmxuYmlCU2IyOTBJRU5CTUI0WERUSXdNRFl4T1RBd01EQTBNbG9YRFRJNE1ERXlPREF3TURBME1sb3dSekVMTUFrR0ExVUVCaE1DVlZNeElqQWdCZ05WQkFvVEdVZHZiMmRzWlNCVWNuVnpkQ0JUWlhKMmFXTmxjeUJNVEVNeEZEQVNCZ05WQkFNVEMwZFVVeUJTYjI5MElGSXhNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXRoRUNpeDdqb1hlYk85eS9sRDYzbGFkQVBLSDlndmw5TWdhQ2NmYjJqSC83Nk51OGFpNlhsNk9NUy9rcjlySDV6b1Fkc2ZuRmw5N3Z1ZktqNmJ3U2lWNm5xbEtyK0NNbnk2U3huR1BiMTVsKzhBcGU2MmltOU1aYVJ3MU5FRFBqVHJFVG84Z1liRXZzL0FtUTM1MWtLU1VqQjZHMDBqMHVZT0RQMGdtSHU4MUk4RTNDd25xSWlydTZ6MWtaMXErUHNBZXduakh4Z3NIQTN5Nm1iV3daRHJYWWZpWWFSUU05c0hta2xDaXREMzhtNWFnSS9wYm9QR2lVVSs2RE9vZ3JGWllKc3VCNmpDNTExcHpycDFaa2o1WlBhSzQ5bDhLRWo4QzhRTUFMWEwzMmg3TTFiS3dZVUgrRTRFek5rdE1nNlRPOFVwbXZNclVwc3lVcXRFajVjdUhLWlBmbWdoQ042SjNDaW9qNk9HYUsvR1A1QWZsNC9YdGNkL3AyaC9yczM3RU9lWlZYdEwwbTc5WUIwZXNXQ3J1T0M3WEZ4WXBWcTlPczZwRkxLY3dacERJbFRpcnhaVVRRQXM2cXprbTA2cDk4ZzdCQWUrZERxNmRzbzQ5OWlZSDZUS1gvMVk3RHprdmd0ZGl6amtYUGRzRHRRQ3Y5VXcrd3A5VTdEYkdLb2dQZU1hM01kK3B2ZXo3VzM1RWlFdWErK3RneS9CQmpGRkZ5M2wzV0ZwTzlLV2d6N3pwbTdBZUtKdDhUMTFkbGVDZmVYa2tVQUtJQWY1cW9JYmFwc1pXd3Bia05GaEhheDJ4SVBFRGdmZzFhelZZODBaY0Z1Y3RMN1RsTG5NUS8wbFVUYmlTdzFuSDY5TUc2ek8wYjlmNkJRZGdBbUQwNnlLNTZtRGNZQlpVQ0F3RUFBYU9DQVRnd2dnRTBNQTRHQTFVZER3RUIvd1FFQXdJQmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCVGtyeXNtY1JvclNDZUZMMUptTE8vd2lSTnhQakFmQmdOVkhTTUVHREFXZ0JSZ2UyWWFSUTJYeW9sUUwzMEV6VFNvLy96OVN6QmdCZ2dyQmdFRkJRY0JBUVJVTUZJd0pRWUlLd1lCQlFVSE1BR0dHV2gwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJkemNqRXdLUVlJS3dZQkJRVUhNQUtHSFdoMGRIQTZMeTl3YTJrdVoyOXZaeTluYzNJeEwyZHpjakV1WTNKME1ESUdBMVVkSHdRck1Da3dKNkFsb0NPR0lXaDBkSEE2THk5amNtd3VjR3RwTG1kdmIyY3ZaM055TVM5bmMzSXhMbU55YkRBN0JnTlZIU0FFTkRBeU1BZ0dCbWVCREFFQ0FUQUlCZ1puZ1F3QkFnSXdEUVlMS3dZQkJBSFdlUUlGQXdJd0RRWUxLd1lCQkFIV2VRSUZBd013RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQURTa0hyRW9vOUMwZGhlbU1Yb2g2ZEZTUHNqYmRCWkJpTGc5TlIzdDVQK1Q0VnhmcTd2cWZNL2I1QTNSaTFmeUptOWJ2aGRHYUpRM2IydDZ5TUFZTi9vbFVhenNhTCt5eUVuOVdwcktBU09zaElBckFveVpsK3RKYW94MTE4ZmVzc21YbjFoSVZ3NDFvZVFhMXYxdmc0RnY3NHpQbDYvQWhTcnc5VTVwQ1pFdDRXaTR3U3R6NmRUWi9DTEFOeDhMWmgxSjdRSlZqMmZoTXRmVEpyOXc0ejMwWjIwOWZPVTBpT015K3FkdUJtcHZ2WXVSN2haTDZEdXBzemZudzBTa2Z0aHMxOGRHOVpLYjU5VWh2bWFTR1pSVmJOUXBzZzNCWmx2aWQwbElLTzJkMXhvemNsT3pnalhQWW92SkpJdWx0emtNdTM0cVFiOVN6L3lpbHJiQ2dqOD0iXX0.eyJub25jZSI6IlF2TDNXRTRydXdzWjB3K2lTdFAyTllYWncwK0lXeS9vVTJGbVpYUjVJRTVsZENCVFlXMXdiR1U2SURFMk5USTNOemsyTVRVME1qZz0iLCJ0aW1lc3RhbXBNcyI6MTY1Mjc3OTYyMzUxMSwiYXBrUGFja2FnZU5hbWUiOiJjb20uZXhhbXBsZS5hbmRyb2lkLnNhZmV0eW5ldHNhbXBsZSIsImFwa0RpZ2VzdFNoYTI1NiI6IkdjTloweVdkcjZ1OUtFQU5Qa1ZpOTUwRE9PaEdjSkZZTHVKc1U5eVVac2M9IiwiY3RzUHJvZmlsZU1hdGNoIjpmYWxzZSwiYXBrQ2VydGlmaWNhdGVEaWdlc3RTaGEyNTYiOlsiV3dOODZXZ3F2UU1zeU1EaFJMOVFhZFZleEQvc1kzS0N5cW5lc0xnN3QzND0iXSwiYmFzaWNJbnRlZ3JpdHkiOmZhbHNlLCJldmFsdWF0aW9uVHlwZSI6IkJBU0lDIn0.kYnbNObgGMQt7nVHFslCGfILMj9Nid8t83pXf8sZxzVm7fqwLMqtUw_TDcLh_zhhSk0-TkuOeI6twjKPeI0LkCUG4Ct1IJP4D6Sc0-hGfz8g5P4888KiUn7Jsz6D2_tS64xSodB8R8miZ05NSQ3Aw9r5uP57U1hI5IX8r4L7Z4wURCR5ktVWarxjhC1QYjyLcZJ5KdSXV1Cz8bebjVFotft7RbFgVTSoI7EHDGSnv-2qI4JMolJnrkyoBwq5iQVVPb40FQp5_L9vniDwtoyV6k5ph-iWrNjRYVVkICe0gR7gKKE20ds1Y8W0_qnT5a0S_8eM49hEX25AgeM88Vrd4g"
var invalidSafetynetJws = "eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGa2pDQ0JIcWdBd0lCQWdJUVJYcm9OMFpPZFJrQkFBQUFBQVB1bnpBTkJna3Foa2lHOXcwQkFRc0ZBREJDTVFzd0NRWURWUVFHRXdKVlV6RWVNQndHQTFVRUNoTVZSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6TVJNd0VRWURWUVFERXdwSFZGTWdRMEVnTVU4eE1CNFhEVEU0TVRBeE1EQTNNVGswTlZvWERURTVNVEF3T1RBM01UazBOVm93YkRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hFekFSQmdOVkJBb1RDa2R2YjJkc1pTQk1URU14R3pBWkJnTlZCQU1URW1GMGRHVnpkQzVoYm1SeWIybGtMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTmpYa3owZUsxU0U0bSsvRzV3T28rWEdTRUNycWRuODhzQ3BSN2ZzMTRmSzBSaDNaQ1laTEZIcUJrNkFtWlZ3Mks5RkcwTzlyUlBlUURJVlJ5RTMwUXVuUzl1Z0hDNGVnOW92dk9tK1FkWjJwOTNYaHp1blFFaFVXWEN4QURJRUdKSzNTMmFBZnplOTlQTFMyOWhMY1F1WVhIRGFDN09acU5ub3NpT0dpZnM4djFqaTZIL3hobHRDWmUybEorN0d1dHpleEtweHZwRS90WlNmYlk5MDVxU2xCaDlmcGowMTVjam5RRmtVc0FVd21LVkFVdWVVejR0S2NGSzRwZXZOTGF4RUFsK09raWxNdElZRGFjRDVuZWw0eEppeXM0MTNoYWdxVzBXaGg1RlAzOWhHazlFL0J3UVRqYXpTeEdkdlgwbTZ4RlloaC8yVk15WmpUNEt6UEpFQ0F3RUFBYU9DQWxnd2dnSlVNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBVEFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUXFCUXdHV29KQmExb1RLcXVwbzRXNnhUNmoyREFmQmdOVkhTTUVHREFXZ0JTWTBmaHVFT3ZQbSt4Z254aVFHNkRyZlFuOUt6QmtCZ2dyQmdFRkJRY0JBUVJZTUZZd0p3WUlLd1lCQlFVSE1BR0dHMmgwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJkMGN6RnZNVEFyQmdnckJnRUZCUWN3QW9ZZmFIUjBjRG92TDNCcmFTNW5iMjluTDJkemNqSXZSMVJUTVU4eExtTnlkREFkQmdOVkhSRUVGakFVZ2hKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd0lRWURWUjBnQkJvd0dEQUlCZ1puZ1F3QkFnSXdEQVlLS3dZQkJBSFdlUUlGQXpBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1b2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwwZFVVekZQTVM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWR3Q2t1UW1RdEJoWUZJZTdFNkxNWjNBS1BEV1lCUGtiMzdqamQ4ME95QTNjRUFBQUFXWmREM1BMQUFBRUF3QklNRVlDSVFDU1pDV2VMSnZzaVZXNkNnK2dqLzl3WVRKUnp1NEhpcWU0ZVk0Yy9teXpqZ0loQUxTYmkvVGh6Y3pxdGlqM2RrM3ZiTGNJVzNMbDJCMG83NUdRZGhNaWdiQmdBSFVBVmhRR21pL1h3dXpUOWVHOVJMSSt4MFoydWJ5WkVWekE3NVNZVmRhSjBOMEFBQUZtWFE5ejVBQUFCQU1BUmpCRUFpQmNDd0E5ajdOVEdYUDI3OHo0aHIvdUNIaUFGTHlvQ3EySzAreUxSd0pVYmdJZ2Y4Z0hqdnB3Mm1CMUVTanEyT2YzQTBBRUF3Q2tuQ2FFS0ZVeVo3Zi9RdEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUk5blRmUktJV2d0bFdsM3dCTDU1RVRWNmthenNwaFcxeUFjNUR1bTZYTzQxa1p6d0o2MXdKbWRSUlQvVXNDSXkxS0V0MmMwRWpnbG5KQ0YyZWF3Y0VXbExRWTJYUEx5RmprV1FOYlNoQjFpNFcyTlJHelBodDNtMWI0OWhic3R1WE02dFg1Q3lFSG5UaDhCb200L1dsRmloemhnbjgxRGxkb2d6L0syVXdNNlM2Q0IvU0V4a2lWZnYremJKMHJqdmc5NEFsZGpVZlV3a0k5Vk5NakVQNWU4eWRCM29MbDZnbHBDZUY1ZGdmU1g0VTl4MzVvai9JSWQzVUUvZFBwYi9xZ0d2c2tmZGV6dG1VdGUvS1Ntcml3Y2dVV1dlWGZUYkkzenNpa3daYmtwbVJZS21qUG1odjRybGl6R0NHdDhQbjhwcThNMktEZi9QM2tWb3QzZTE4UT0iLCJNSUlFU2pDQ0F6S2dBd0lCQWdJTkFlTzBtcUdOaXFtQkpXbFF1REFOQmdrcWhraUc5dzBCQVFzRkFEQk1NU0F3SGdZRFZRUUxFeGRIYkc5aVlXeFRhV2R1SUZKdmIzUWdRMEVnTFNCU01qRVRNQkVHQTFVRUNoTUtSMnh2WW1Gc1UybG5iakVUTUJFR0ExVUVBeE1LUjJ4dlltRnNVMmxuYmpBZUZ3MHhOekEyTVRVd01EQXdOREphRncweU1URXlNVFV3TURBd05ESmFNRUl4Q3pBSkJnTlZCQVlUQWxWVE1SNHdIQVlEVlFRS0V4VkhiMjluYkdVZ1ZISjFjM1FnVTJWeWRtbGpaWE14RXpBUkJnTlZCQU1UQ2tkVVV5QkRRU0F4VHpFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUURRR005RjFJdk4wNXprUU85K3ROMXBJUnZKenp5T1RIVzVEekVaaEQyZVBDbnZVQTBRazI4RmdJQ2ZLcUM5RWtzQzRUMmZXQllrL2pDZkMzUjNWWk1kUy9kTjRaS0NFUFpSckF6RHNpS1VEelJybUJCSjV3dWRnem5kSU1ZY0xlL1JHR0ZsNXlPRElLZ2pFdi9TSkgvVUwrZEVhbHROMTFCbXNLK2VRbU1GKytBY3hHTmhyNTlxTS85aWw3MUkyZE44RkdmY2Rkd3VhZWo0YlhocDBMY1FCYmp4TWNJN0pQMGFNM1Q0SStEc2F4bUtGc2JqemFUTkM5dXpwRmxnT0lnN3JSMjV4b3luVXh2OHZObWtxN3pkUEdIWGt4V1k3b0c5aitKa1J5QkFCazdYckpmb3VjQlpFcUZKSlNQazdYQTBMS1cwWTN6NW96MkQwYzF0Skt3SEFnTUJBQUdqZ2dFek1JSUJMekFPQmdOVkhROEJBZjhFQkFNQ0FZWXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0VHQ0NzR0FRVUZCd01DTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0hRWURWUjBPQkJZRUZKalIrRzRRNjgrYjdHQ2ZHSkFib090OUNmMHJNQjhHQTFVZEl3UVlNQmFBRkp2aUIxZG5IQjdBYWdiZVdiU2FMZC9jR1lZdU1EVUdDQ3NHQVFVRkJ3RUJCQ2t3SnpBbEJnZ3JCZ0VGQlFjd0FZWVphSFIwY0RvdkwyOWpjM0F1Y0d0cExtZHZiMmN2WjNOeU1qQXlCZ05WSFI4RUt6QXBNQ2VnSmFBamhpRm9kSFJ3T2k4dlkzSnNMbkJyYVM1bmIyOW5MMmR6Y2pJdlozTnlNaTVqY213d1B3WURWUjBnQkRnd05qQTBCZ1puZ1F3QkFnSXdLakFvQmdnckJnRUZCUWNDQVJZY2FIUjBjSE02THk5d2Eya3VaMjl2Wnk5eVpYQnZjMmwwYjNKNUx6QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFHb0ErTm5uNzh5NnBSamQ5WGxRV05hN0hUZ2laL3IzUk5Ha21VbVlIUFFxNlNjdGk5UEVhanZ3UlQyaVdUSFFyMDJmZXNxT3FCWTJFVFV3Z1pRK2xsdG9ORnZoc085dHZCQ09JYXpwc3dXQzlhSjl4anU0dFdEUUg4TlZVNllaWi9YdGVEU0dVOVl6SnFQalk4cTNNRHhyem1xZXBCQ2Y1bzhtdy93SjRhMkc2eHpVcjZGYjZUOE1jRE8yMlBMUkw2dTNNNFR6czNBMk0xajZieWtKWWk4d1dJUmRBdktMV1p1L2F4QlZielltcW13a201ekxTRFc1bklBSmJFTENRQ1p3TUg1NnQyRHZxb2Z4czZCQmNDRklaVVNweHU2eDZ0ZDBWN1N2SkNDb3NpclNtSWF0ai85ZFNTVkRRaWJldDhxLzdVSzR2NFpVTjgwYXRuWnoxeWc9PSJdfQ.eyJub25jZSI6InRhbXBlcmVkIiwidGltZXN0YW1wTXMiOjE1NTM3NDA2MTkwMDksImFwa1BhY2thZ2VOYW1lIjoiY29tLmV4YW1wbGUuc2FmZXR5bmV0dGVzdCIsImFwa0RpZ2VzdFNoYTI1NiI6ImkvdkM2ZU5hS0pPVWUwYmx2ZlhGS08ycGEyQytoQ09RWWFWa2tOL2V1Q2c9IiwiY3RzUHJvZmlsZU1hdGNoIjp0cnVlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyJCZ1JySDl0N3lERVQ3eVYrOUEwMU0vb2U5anRoQ0VDUDhDdG54SmlYRUhRPSJdLCJiYXNpY0ludGVncml0eSI6dHJ1ZX0.yhQSNUP3N86F4Pas_d43sa8GdSjhNtU_FQZvn7obOWuLnTLtpGRjzA-5YBQezQsP35bnFrZspFl5GWeHZzbcciClG-Ph_mZ9vhnLo__jf-h2SMgR2ScXQNEPavaCm9KjZsIpUi1y3skJAUbfaCNcMJSfdh0qSn3Oxdk02FO-qRhntUwwJj-_bQrszUNLo-5yCovxMr_-AjE3ENz6W7IH01JhzG7h-sHkRrzQBY9aO35NZjmCTZiTSuP9n0_vfJslz-Skh07qeQzCaqkz2JYDhwyu2spnycqIGhNDEb1i0rll7JkUj8Gp4YZCq6YcMgxqZJokTWvfcgGwx-xIjZzZzw"

func TestValidateNew(t *testing.T) {
	assert := assert.New(t)

	/*
		safetynet.TimeFunction = func() time.Time {
			return time.Date(2019, 5, 1, 0, 0, 0, 0, time.FixedZone("UTC", 0))
		}
	*/
	attestation, err := safetynet.ValidateNew(safetynetJws)
	assert.Nil(err)
	assert.Equal(int64(1553740619009), attestation.Timestamp)
	assert.Equal(int64(1553740619009000000), attestation.GetTimestamp().UnixNano())
	assert.Equal("", attestation.Nonce)
	assert.Equal("com.example.safetynettest", attestation.ApkPackageName)
	assert.Equal("i/vC6eNaKJOUe0blvfXFKO2pa2C+hCOQYaVkkN/euCg=", attestation.ApkDigestSHA256)
	assert.Equal([]string{"BgRrH9t7yDET7yV+9A01M/oe9jthCECP8CtnxJiXEHQ="}, attestation.ApkCertificateDigestSHA256)
	assert.Equal("", attestation.Error)
	assert.Equal(true, attestation.CTSProfileMatch)
	assert.Equal(false, attestation.BasicIntegrity)

	_, err = safetynet.ValidateNew(invalidSafetynetJws)
	assert.NotNil(err)
}
