Return-Path: <kasan-dev+bncBC6OLHHDVUOBBH54W7CAMGQEQPIG4DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F84B18D37
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:45:05 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3139c0001b5sf2645638a91.2
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:45:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127904; cv=pass;
        d=google.com; s=arc-20240605;
        b=L3SUW+0kVBOI+qWgZgTWIGcCjvVoLBP6CZGfCFKvy7DN7ggpDvlYzxX2PNRlj4sMSm
         4PElV0Vm2FGYSaG0KsFs5886Y7nzXYZIZVg7tdng+/8Q4sfi6nDtypbDex3LW56g1obY
         A4mbro03olcTf54hdAezGlw8aIwkfQ3KUWBVWsH9OgpZ40JlrklV23KFELc3OIeMsatR
         wT1F9xx8f/l4TZYqQaKZ+0H1zhP3kl4M3hiBLGBca9eHNWXdr/298bBRSYn6FKH4N8Ql
         njXogPwHXDNwYiay/1rIyb+yvoKfYv8ZEZQxnp68vVKDwWTgLPJKw+0kMnct/sIHjKpv
         N1nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uLSzZu4vihp9KD9K8amNaIETGqH5Yivx5w//OKGFUXA=;
        fh=dKPR0kj8sHkUQHY0RDGDEoFX6M7vJkD9177IAk2upcQ=;
        b=SGIspoQUklgLZA98M4woLa2ptiPcOt6ZVq/ZMegvoXLcZV9yFjVdcJyvn+u4EUv+Bz
         utbYXtm8sJmM8daN8/RlJHkt0l8bn1coD3Yyk/+9P4fBCQE0cl55s/XlzJigdATUaek1
         EtFddEotW/eFelvmhMWDAZ64LX5mGy0mKw/dXY+xluRqif5JKo3OlH0XpAnSxZbLVdQh
         o/ELtSVBTbFC2jzSwD4UArDKU/rQBQ9lbpRYnvOAvtA+x8O0XoB5b50jEY5LaBrZRHcT
         KYtJGclSse3QrOfM4z/kZ//jBP0rt0KqMN4HCIoZFXA39hrcTAmcWr8jy+vAU63SOVJq
         +u2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h6yXqnM8;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127904; x=1754732704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uLSzZu4vihp9KD9K8amNaIETGqH5Yivx5w//OKGFUXA=;
        b=EeNjESSyD4JCflCG5rpDnyrwmMSHUt5sRmfIfl02bHGxRErlgjQ8sPZ1yo7Sdat/q7
         f6Q+alz9D2j5FtvajMvWGxDhS8jy31TmWSeyNr3BJXcEW7hEHA2tpXYDH7Tkg17j1BWy
         qRN+ya1zDyhag6amp/2Qpb+PEOUJceHZtYHmFhGgg90Ue0SJ+PW8cG9Si9IyjzhQv55j
         aqvENAL7MhTSo6E5XgwmrPtdSKBiG+e0sEh/2GrdChSV9GMZu82jINob7xyG2IyP44QX
         BxhhhtxxCzCgHRsrFc8+yP3H0VVoEapHMznecaJUFt/EHWTSj4vjfglS0oV4wSMC9P+i
         KdUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127904; x=1754732704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uLSzZu4vihp9KD9K8amNaIETGqH5Yivx5w//OKGFUXA=;
        b=v3D6FxmMVUIAQV1STJuynvE0WGYA7cxYM3wXoAeM6+9HYKLhxictP93PSyOsglSgra
         9g9WgiitAUJzcaXnX8+FR7DYHVglM18/TKqh/1bZukdtcschN/kCcZ0XSZ+oEHpgcHk5
         dLFGqLuqnsBKmTTK0PylM6DHaHanIHxg49UqwE7BgCZPSddUJTrsAtjOXzqN/6ID0CEc
         iSMXiDkgj3c89pgiKYpo2DQr+KOSIYvgq1K3apkPm7dhDIVkhl3VlOYnyt5Lv7EX0S97
         BoVOjxmEsCvKVnGGU0rXGjoyiK5VQlkolOWy2BeqtvoRL4asDc4MDmI1cyavvs7sRqsr
         0wng==
X-Forwarded-Encrypted: i=2; AJvYcCWgcX6eO+K7knGtVvKO6tq6KwKlF1fqEkPM7WtckOw/5B3JWgWM8paoPpLeQXyjBbwtNgRpLg==@lfdr.de
X-Gm-Message-State: AOJu0YxQ4RWA9HB5E9qe/lxZ88neJ7JDjRNYHA/ZXPj/TWaajytYLxDM
	LZ6JkmcuFlT+eycI5FvqptU/Z81/cFlH4YXRvKTvjGkkW7FK+3+34jyP
X-Google-Smtp-Source: AGHT+IHA7Le87/Q1Ml1b4lVbft3jT5PRE4EnCkhWZ8eOHxxFO195UzMqC6MHhOqVZ22Htt6/mpiaFg==
X-Received: by 2002:a17:90a:e7d2:b0:31e:e88b:ee0d with SMTP id 98e67ed59e1d1-321161f2e04mr4346166a91.9.1754127903929;
        Sat, 02 Aug 2025 02:45:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeK86RoEmXHlY5UynFIjwOG6Vb2iuHTYR2jHF8Fq9u0Sw==
Received: by 2002:a17:90b:48c2:b0:31e:f3b1:2e6f with SMTP id
 98e67ed59e1d1-31f90c62159ls3023496a91.2.-pod-prod-05-us; Sat, 02 Aug 2025
 02:45:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvRvMhPbTXE3KRZpX0z3uf4S2+n+uiMDMikqsLQDer5WaJ5SzQbozZ9HZvYb3NrpDLAe8bjPkhMic=@googlegroups.com
X-Received: by 2002:a05:6a20:4309:b0:23d:dd9b:b51b with SMTP id adf61e73a8af0-23df8fbfbb4mr4294839637.11.1754127902376;
        Sat, 02 Aug 2025 02:45:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127902; cv=none;
        d=google.com; s=arc-20240605;
        b=l1g33WroCObMooJzm8UL5VHHRU70mekwDpBF/+JBEAPJPWR4pwVEkv2y5SJuPX6azU
         p0/O0oVh3xwNvZOhtYreGV44vi82gRuMH3mMtDm9VlW7QDXw08p+A/u+3rnh/cGdHlw+
         v9i3/sGtgXphr+cSTStGviOlc7SFibiJlMTguYayTRBjo8LFmBmuRsdXXke7NjQFaLxF
         bCm9btHn9uQhAHqCPMN2dkgHN96p+PLwvT6pkv21RWnihqPg+QWFytG8fVqaSgXAchQ1
         5YpH2MyFLn+RhW3cnwP/PuLuEbZ8msnvAJ8pef+kEkLHPA6c+VJKaQ99NI+/dn8XKrhH
         zvZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cwiw+3AyfHADH+0Nt5aZJ7BKpYdICPRhSxfX8ZcOKOk=;
        fh=vFDCkvKb8ADJ8Y2/gJR7ALn4pICDmMaWpQEE8H0fo4Y=;
        b=a9sPZh85cS4Pdyg7CNaoj0RaJmTbL/lJHKBvG0HFYEkHA6EHCoQ9CLdw1jtW6xMFAV
         tZfGtPGgwcnO//dGT90P0CAFUiIAPxt+BBrVu7HqdOi95923B46E5zXd/DtbzJbqFDqI
         CByfPcrufA58jKjn7lrpkCWOcOKVfjrMBYFBqPg13oQ/Yr9OSLc6uY8QWLJG6DnI3i9A
         YLJHX0jb4ygdohBTuJQmpHVmJc9zQkwUnKY3gq9shHrMwgbGRXrZqo9YjdyEXTWl9nd1
         7JOBC6GQh8j1VZXDOcjOMaMoashikG//yrZbvKlfDq8CjCL/ATDsp/ROAyYzI0BgZEjP
         rIPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h6yXqnM8;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b422b7beb9csi162473a12.1.2025.08.02.02.45.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:45:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-4af123c6fc4so7641431cf.0
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:45:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXO2apH/gGhXF2iAtcxVCT8zx2RYfLvTMsSynTzaopWR7j17XA2kmatw1DmYAzCMCqORbeXhPP60LY=@googlegroups.com
X-Gm-Gg: ASbGncvDA7DYO/hcrgREy5PZ73C0y/ocwxkOFHMzbU95CLFG2R53UzMtU5CGxZs8KNH
	TQbSvzXOSOhLJ56l3M4hJUhJf2t+I+f7wm0Y3Zgd0RNVrNMyx0ZiubW1/BtrirdVvTW1E6s0KCL
	AvLwF82Q6fpr02vU6cA981AKsdowVSSNrzFU2Kva3kjld1fxb+tX1UpOoIo7V5UjA3MBwYRqJRQ
	lh3wViREugs2qCDoCE=
X-Received: by 2002:ac8:5802:0:b0:4ab:6c75:620 with SMTP id
 d75a77b69052e-4af10954c19mr47286961cf.1.1754127901186; Sat, 02 Aug 2025
 02:45:01 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-6-marievic@google.com>
In-Reply-To: <20250729193647.3410634-6-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:48 +0800
X-Gm-Features: Ac12FXxzj7NJuQfaw5YMY9Xgg-cu4_yvgrPf9Wxf5hDCWeBmCbl6q73Q5jmH-lY
Message-ID: <CABVgOSmTNAOoLqLhsZq+RiBU3wj4s79hzV+WFEOS10sahZf6Mg@mail.gmail.com>
Subject: Re: [PATCH 5/9] drm/xe: Update parameter generator to new signature
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="0000000000007a72a7063b5ebaaf"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=h6yXqnM8;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::835
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

--0000000000007a72a7063b5ebaaf
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> This patch modifies `xe_pci_live_device_gen_param`
> in xe_pci.c to accept an additional `struct kunit *test`
> argument.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---


This is a pretty straightforward fix after patch 3. xe folks, would
you prefer this kept as a separate patch, or squashed into patch 3
(which changed the function signature)?

Either way,
Reviewed-by: David Gow <davidgow@google.com>


-- David


>  drivers/gpu/drm/xe/tests/xe_pci.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests/xe_pci.c
> index 1d3e2e50c355..62c016e84227 100644
> --- a/drivers/gpu/drm/xe/tests/xe_pci.c
> +++ b/drivers/gpu/drm/xe/tests/xe_pci.c
> @@ -129,7 +129,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
>   * Return: pointer to the next &struct xe_device ready to be used as a parameter
>   *         or NULL if there are no more Xe devices on the system.
>   */
> -const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
> +const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc)
>  {
>         const struct xe_device *xe = prev;
>         struct device *dev = xe ? xe->drm.dev : NULL;
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmTNAOoLqLhsZq%2BRiBU3wj4s79hzV%2BWFEOS10sahZf6Mg%40mail.gmail.com.

--0000000000007a72a7063b5ebaaf
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIUnQYJKoZIhvcNAQcCoIIUjjCCFIoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ghIEMIIGkTCCBHmgAwIBAgIQfofDAVIq0iZG5Ok+mZCT2TANBgkqhkiG9w0BAQwFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMzA0MTkwMzUzNDdaFw0zMjA0MTkwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFI2IFNNSU1FIENBIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYydcdmKyg
4IBqVjT4XMf6SR2Ix+1ChW2efX6LpapgGIl63csmTdJQw8EcbwU9C691spkltzTASK2Ayi4aeosB
mk63SPrdVjJNNTkSbTowej3xVVGnYwAjZ6/qcrIgRUNtd/mbtG7j9W80JoP6o2Szu6/mdjb/yxRM
KaCDlloE9vID2jSNB5qOGkKKvN0x6I5e/B1Y6tidYDHemkW4Qv9mfE3xtDAoe5ygUvKA4KHQTOIy
VQEFpd/ZAu1yvrEeA/egkcmdJs6o47sxfo9p/fGNsLm/TOOZg5aj5RHJbZlc0zQ3yZt1wh+NEe3x
ewU5ZoFnETCjjTKz16eJ5RE21EmnCtLb3kU1s+t/L0RUU3XUAzMeBVYBEsEmNnbo1UiiuwUZBWiJ
vMBxd9LeIodDzz3ULIN5Q84oYBOeWGI2ILvplRe9Fx/WBjHhl9rJgAXs2h9dAMVeEYIYkvW+9mpt
BIU9cXUiO0bky1lumSRRg11fOgRzIJQsphStaOq5OPTb3pBiNpwWvYpvv5kCG2X58GfdR8SWA+fm
OLXHcb5lRljrS4rT9MROG/QkZgNtoFLBo/r7qANrtlyAwPx5zPsQSwG9r8SFdgMTHnA2eWCZPOmN
1Tt4xU4v9mQIHNqQBuNJLjlxvalUOdTRgw21OJAFt6Ncx5j/20Qw9FECnP+B3EPVmQIDAQABo4IB
ZTCCAWEwDgYDVR0PAQH/BAQDAgGGMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYJKwYB
BAGCNxUGBgkrBgEEAYI3FQUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUM7q+o9Q5TSoZ
18hmkmiB/cHGycYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEE
bzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsG
AQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMBEG
A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAVc4mpSLg9A6QpSq1JNO6tURZ4rBI
MkwhqdLrEsKs8z40RyxMURo+B2ZljZmFLcEVxyNt7zwpZ2IDfk4URESmfDTiy95jf856Hcwzdxfy
jdwx0k7n4/0WK9ElybN4J95sgeGRcqd4pji6171bREVt0UlHrIRkftIMFK1bzU0dgpgLMu+ykJSE
0Bog41D9T6Swl2RTuKYYO4UAl9nSjWN6CVP8rZQotJv8Kl2llpe83n6ULzNfe2QT67IB5sJdsrNk
jIxSwaWjOUNddWvCk/b5qsVUROOuctPyYnAFTU5KY5qhyuiFTvvVlOMArFkStNlVKIufop5EQh6p
jqDGT6rp4ANDoEWbHKd4mwrMtvrh51/8UzaJrLzj3GjdkJ/sPWkDbn+AIt6lrO8hbYSD8L7RQDqK
C28FheVr4ynpkrWkT7Rl6npWhyumaCbjR+8bo9gs7rto9SPDhWhgPSR9R1//WF3mdHt8SKERhvtd
NFkE3zf36V9Vnu0EO1ay2n5imrOfLkOVF3vtAjleJnesM/R7v5tMS0tWoIr39KaQNURwI//WVuR+
zjqIQVx5s7Ta1GgEL56z0C5GJoNE1LvGXnQDyvDO6QeJVThFNgwkossyvmMAaPOJYnYCrYXiXXle
A6TpL63Gu8foNftUO0T83JbV/e6J8iCOnGZwZDrubOtYn1QwggWDMIIDa6ADAgECAg5F5rsDgzPD
hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
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
jmkLAgMBAAGjggHgMIIB3DAeBgNVHREEFzAVgRNkYXZpZGdvd0Bnb29nbGUuY29tMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYDVR0OBBYEFBp5bTxrTm/d
WMmRETO8lNkA4c7fMFgGA1UdIARRME8wCQYHZ4EMAQUBAjBCBgorBgEEAaAyCgMDMDQwMgYIKwYB
BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQC
MAAwgZoGCCsGAQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWdu
LmNvbS9jYS9nc2F0bGFzcjZzbWltZWNhMjAyMzBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3J0MB8GA1UdIwQYMBaA
FDO6vqPUOU0qGdfIZpJogf3BxsnGMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFs
c2lnbi5jb20vY2EvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBF
tO3/N2l9hTaij/K0xCpLwIlrqpNo0nMAvvG5LPQQjSeHnTh06tWTgsPCOJ65GX+bqWRDwGTu8WTq
c5ihCNOikBs25j82yeLkfdbeN/tzRGUb2RD+8n9I3CnyMSG49U2s0ZdncsrIVFh47KW2TpHTF7R8
N1dri01wPg8hw4u0+XoczR2TiBrBOISKmAlkAi+P9ivT31gSHdbopoL4x0V2Ow9IOp0chrQQUZtP
KBytLhzUzd9wIsE0QMNDbw6jeG8+a4sd17zpXSbBywIGw7sEvPtnBjMaf5ib3kznlOne6tuDVx4y
QFExTCSrP3OTMUkNbpIdgzg2CHQ2aB8i8YsTZ8Q8Q8ztPJ+xDNsqBUeYxILLjTjxQQovToqipB3f
6IMyk+lWCdDS+iCLYZULV1BTHSdwp1NM3t4jZ8TMlV+JzAyRqz4lzSl8ptkFhKBJ7w2tDrZ3BEXB
8ASUByRxeh+pC1Z5/HhqfiWMVPjaWmlRRJVlRk+ObKIv2CblwxMYlo2Mn8rrbEDyfum1RTMW55Z6
Vumvw5QTHe29TYxSiusovM6OD5y0I+4zaIaYDx/AtF0mMOFXb1MDyynf1CDxhtkgnrBUseHSOU2e
MYs7IqzRap5xsgpJS+t7cp/P8fdlCNvsXss9zZa279tKwaxR0U2IzGxRGsWKGxDysn1HT6pqMDGC
Al0wggJZAgEBMGgwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKjAo
BgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMwIQAUXA7LnOuRz2DvkWTeMc
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgCW07HzC0aE661vW+3P7Bv0AG9Nbo
KmvKergx6moXAzAwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NTAxWjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAYWKXavasvHqVN7tILps3q0AelnwvSIP8Q4+OqW8nzGavNL4ngLkSY30gqlMHydBs
lIX9FDZqZqVUDNIIHVq8EWcCRA77nHgy0WZoxfvO36LF0rAyuJYCxSmWryaxyen89bAEDecnMaEl
zNldtXN/WY8jYbYy7D3qXDsCF2FKZUqJbXai/ccZZJb5ruxLdMVFh4S6LSzMWV0p4eV3aDgwwM4F
42yZ6ZpjMpFxzk/yo90+d/29ZBZGXXYL9IDw3MGCvNrj8ht8x+zYIHBAfoGoxvoGHLInTUxBFDN0
xQdRLeOvcFj0s/nMtda4xowTW0O+IP9RMxjt8jJERSj7LJJ1rg==
--0000000000007a72a7063b5ebaaf--
