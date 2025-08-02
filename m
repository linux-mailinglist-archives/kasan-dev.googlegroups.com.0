Return-Path: <kasan-dev+bncBC6OLHHDVUOBBHN4W7CAMGQE3I2KJAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id EA89AB18D34
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:45:02 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70739ef4ab4sf42824346d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:45:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127902; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZDt8/R19IJC/B8YXFktqc1pqZfotT5LIk5K3WXy/qrPoH6YGiJ4OLiWCh9C3FHwL2m
         OvMDTtMiR3mtSh4zjwKdKbL5Ms/VjhxLgB0wS4RUTuQ95AMizfGIXAIl7L+ULaT4VBKC
         JOq2LVi/Gn+A0fhf+c0M4F1UxEBUQDOU1QmyoMfYIrVFzdoAHL+KihHttITkCK31/zA7
         svhPc9tDXY9ssxzDxNPtm2LOcbfeOLNQQNsrxJv6YTaCRzcqJH2hm9SZBylA4tx4xjF7
         YFbWfHVxpEcrzLqt8ulscvenO+TnwIJYYIE3kJUZKwZGh2mihrqVg9jbOVBeGR42bXep
         dFvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mVJRAbBAPGrPGe/eYjdX4K+fkJ3rq1wypFW/hXFhAFY=;
        fh=qjxrZBrYpz43Okis1MzZ5FLnrys2Dq1h+hZIgdzn8dY=;
        b=CYjUF8PDdUb2Jb4WgS1dOzDIYOgZ00QlaxjVs8dqZNKXYOHAMqwryJr2Z9H8gjWeTx
         0bhnX8AX5IlPv8IsvvKWcg5HF1m6gzJp+jKMRxJ80zVdLYQb4Mz6aFaQy83eu0jM+Wt1
         vp6WxwuCJHUYl7evfPjwSgIsqhCHdI9V5wzTw8nKW29D9ajLLzTuB+HfRjSyy8rRShSE
         PfS+79v5X2Rplq1SYOzxBZNMCYsxKJ5J+FEPGYK/8fuq/R/gHi3cCOgHVd1k/+g2n4e3
         3T4Erz0BF+jDW5yQABlYv/lNEs8dcu4C1fOFAaiqs/sVk2H8nxy9bjMVAxrBFRKnDfQk
         8sIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UGelSZCC;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127902; x=1754732702; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mVJRAbBAPGrPGe/eYjdX4K+fkJ3rq1wypFW/hXFhAFY=;
        b=xN1g5uCFGGsafUvVVispWDn7Nn/XTxPcToWsp0m+iW5AqGPezMWu4cQ+uVj1zWUa3S
         2kWzquW9IqU2DwtLvmEltahJEsg2QHlmhB7xYwIH8AeXJ2unrcpEAzimaZtyQG2Gqr/W
         9Fo9MbS5Q8o6Ifs4fGgRtsJfMwR4tchsDKt3hASHxgWxp2hgMk8fN0YbXv8U/r1G7vql
         7lJNFukc7U4mXSxzObSgXv17LmhO7faX7UabNN6BhRjrsGQl6vrNkWuQyKsj12hy9hJ1
         48DE153+NluRyvwtlrcgi48XXlLS5kmI6Il5WdFpQbFM1NXR5/+hpJ/xugdYF9mrhnW6
         Et2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127902; x=1754732702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mVJRAbBAPGrPGe/eYjdX4K+fkJ3rq1wypFW/hXFhAFY=;
        b=dWdJA6Bn8YQbvOkdgxFZ1AUBCfpryA+07/AKRWnQpx7Vl/o5+qnfHAUy6VUh8RW1pM
         J9pQcPB7MrCE1qo32NzfJd5cO5GE+zQsKowsoOVOZtu0c9HHXSU0tXpy+Pk/nb28tb10
         bpwUw0bBDidcPvVCEDIsyO2PyCNBVE+FHm4CUgfKg0cKXUz9A2joqGluifZ2XL8vhV9z
         44pMl88jEsWsNbx0vDmhBDgHkn7ZloKCMa6zwnyG6OlQc/OpJftnARVP6+Q1WV05daHy
         e1aAt0EmBHaSO8GL1eMFtVeo2+SlrsN7xHH9fublKBzwuQ4TmymB/kvFAhY5Cz0wl/zD
         o1JA==
X-Forwarded-Encrypted: i=2; AJvYcCUTY1DhjV2L9Q2nv87tqXwZlTSuJaq0UntL4C1VV25/V29bib2MlNMHlYkL7HzOS363a9/t2g==@lfdr.de
X-Gm-Message-State: AOJu0YxuXif7t5jazU76bHu7Y4bIV7baCH3Fp4BOgtvff2fPh9PQa3E1
	4rBr9MOROb68lRtz6s7RpW4h/qr/UWGmNdLmlLHTpK74sGia2kVl2Vut
X-Google-Smtp-Source: AGHT+IGzIqXW37gPLoh6KI7Gwf13R9NXWlq6S82JzoKQDLXLeWblF3donge+nNNfA2Ap+WZ47neYXQ==
X-Received: by 2002:a05:6214:482:b0:707:6409:d016 with SMTP id 6a1803df08f44-70935f60153mr38126826d6.9.1754127901714;
        Sat, 02 Aug 2025 02:45:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfdI+7Vn5SFF1qID21QV85Ng7+G0pX27Yj2TPVX0T8xJw==
Received: by 2002:a05:6214:da8:b0:707:1f59:62a2 with SMTP id
 6a1803df08f44-70778d6c1dals26339006d6.1.-pod-prod-00-us; Sat, 02 Aug 2025
 02:45:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUX6Zv69kxFy8PfG6yeGnx1neTE7v/vk6qO4qHqG8guQsMAWlCgrAck+6Y9qrnzigmoiL+W2xNk+ZM=@googlegroups.com
X-Received: by 2002:a05:620a:51d1:b0:7dc:86f1:ee1a with SMTP id af79cd13be357-7e696518214mr326322485a.11.1754127900744;
        Sat, 02 Aug 2025 02:45:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127900; cv=none;
        d=google.com; s=arc-20240605;
        b=k10lxLnUpASPlPS52WPak++X5/1CSY2U8f4PpZRCHpeTL4S4NJrQdE7WbEK+G9WHl7
         4FryKodhMLzAOEmx+/rmbrk+VRM5KYOiE0K9I4lndMI7DBG4ysM+6XSbBG7Wu1rTd53h
         lgbJdu1A+3XMJ9yJL/QbJysyEt1QGNH/NwtPG6LZrzO2wAvYUwm73soPyxt6BU2SMuiZ
         mYRcJN/vJMOAtoKIEqmB6b86cTamUc4cJFX/QSJKrh3t28k8evONTu534gMhhrJ5qroi
         IVZGh6n0ObnLEAkcb438++CJPIpzTG7CcG7l5RW1FYihZOC4ipZE/o9kGI9ynXuRhTZh
         Inqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uavsR3Y/AsgQ7di4LEqq5z4fP13okmtwckiffQ5ItX4=;
        fh=dFoNKDBbrxDpyqfPZQwVE/myg29vzEldkCQLrNqsrHg=;
        b=ZgEAeTTpTz2BWLP+T6Uw4F2JOaSgOHQUxZKQb712OTy6E7oTmACZEDSFERoEEtBzWi
         OfRTrVs99QBt/2qB7vcJcgSo24R5TWCiwtlEgM8nDp3ngwrqND2CyklaxDUyXAcHJ9N7
         sDm4D6x7uy4l/T63lKXWPcPLfznZApWzZvVlaKgMvWXkHR6ug9+FxAmYEZsLnbFNXPbi
         CWMBUukNNzpUzG/4uFF+oViqmbOi0MwReM8yqok6NUORvHOA/+t/Y/cf4D+TMnnVlZUU
         a12zTssGeZ8wd3iDUyPUvd564Bl6XrvtLI7v1SuwhLubzrWKwBjUt56azkjtSR2DBJ87
         yARg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UGelSZCC;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e68b4b2c8esi14700185a.5.2025.08.02.02.45.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:45:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-70875cc3423so23254726d6.0
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:45:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqgazCs+J9YJ4xlukTxPkNnSrg2ErhbQHim7GRv7cKp8sW5LlXzSNcbhbWrG4uBaonOLD8zifaW0o=@googlegroups.com
X-Gm-Gg: ASbGncv+O5SUp4zBI4PD8KdWBszZnBseX+apjUWv4roHFT8DIKt++cpbNAG3z/IMIhr
	V8Tl6TbwW3MyPLqH8T36zKofiLCWNZO16G51tLXNQnxtQwHEC+LosSOFnvEEYKTCejnrzPMuTEt
	N/ivkfpSIrjM/d3Lmd7P3WaGBc9qli0zAHqSw9jRFZyILlvPi1z56JfqKgvxgBMuX4m6bqrwwsc
	kZfa7Wm
X-Received: by 2002:a05:6214:482:b0:707:6409:d016 with SMTP id
 6a1803df08f44-70935f60153mr38126276d6.9.1754127900103; Sat, 02 Aug 2025
 02:45:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-5-marievic@google.com>
In-Reply-To: <20250729193647.3410634-5-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:45 +0800
X-Gm-Features: Ac12FXyD0NUtg84q97c-X3R9eBKapNZWOLNwLnhlzJzZ5xtYlZgKpFxg0pby0ik
Message-ID: <CABVgOSnmtcjarGuZog9zKNvt9rYD2Tsox3ngVgh4pJUFMF737w@mail.gmail.com>
Subject: Re: [PATCH 4/9] kcsan: test: Update parameter generator to new signature
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="0000000000006974eb063b5ebabd"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UGelSZCC;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f2c
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

--0000000000006974eb063b5ebabd
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> This patch modifies `nthreads_gen_params` in kcsan_test.c
> to accept an additional `struct kunit *test` argument.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

This is a pretty straightforward fix after patch 3. KCSAN folks, would
you prefer this kept as a separate patch, or squashed into the
previous one (so there's no commit where this is broken)?

Either way,
Reviewed-by: David Gow <davidgow@google.com>


-- David

>  kernel/kcsan/kcsan_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index c2871180edcc..fc76648525ac 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
>   * The thread counts are chosen to cover potentially interesting boundaries and
>   * corner cases (2 to 5), and then stress the system with larger counts.
>   */
> -static const void *nthreads_gen_params(const void *prev, char *desc)
> +static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
>  {
>         long nthreads = (long)prev;
>
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnmtcjarGuZog9zKNvt9rYD2Tsox3ngVgh4pJUFMF737w%40mail.gmail.com.

--0000000000006974eb063b5ebabd
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
NjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAw
MDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5
KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hY
dLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEW
P3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoR
h3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sI
ScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HU
Gie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZip
W6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKs
o+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y
/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99w
MOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge
/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJ
U7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnA
ZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDCCBeQwggPMoAMCAQICEAFFwOy5zrkc9g75Fk3jHNEw
DQYJKoZIhvcNAQELBQAwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
KjAoBgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMzAeFw0yNTA2MDEwODEx
MTdaFw0yNTExMjgwODExMTdaMCQxIjAgBgkqhkiG9w0BCQEWE2RhdmlkZ293QGdvb2dsZS5jb20w
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqxNhYGgWa19wqmZKM9x36vX1Yeody+Yaf
r0MV27/mVFHsaMmnN5CpyyGgxplvPa4qPwrBj+5kp3o7syLcqCX0s8cUb24uZ/k1hPhDdkkLbb9+
2Tplkji3loSQxuBhbxlMC75AhqT+sDo8iEX7F4BZW76cQBvDLyRr/7VG5BrviT5zFsfi0N62WlXj
XMaUjt0G6uloszFPOWkl6GBRRVOwgLAcggqUjKiLjFGcQB5GuyDPFPyTR0uQvg8zwSOph7TNTb/F
jyics8WBCAj6iSmMX96uJ3Q7sdtW3TWUVDkHXB3Mk+9E2P2mRw3mS5q0VhNLQpFrox4/gXbgvsji
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgXPQTK0+ipCXOMwEjmbPfX9pH7GwC
UVAtSzbrKFbxDgwwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NTAwWjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEACuCHPAr/DyWesPxG5G7lzBTPMRvbSE6a17lHmIJGH53lwLm3SwbuF2KfOuqNEfgV
YSgKvJQrwQRRBIRy8WnaXDfFfGK5OzyGKsBB06mqFKW6I5ArVNvg2JkK+/G7Prg3a7COI+yPim+6
JGFpPhNxCD9iKlQrllG6W/QUYPCxNZ6UQIGSPcYSkEGtp4TmreJqsLUtAcu4KnYhLkoqywnUEDVG
PTRHXJP3dWHw4sL+0mlsPWQHFYEzbnhegu7cLhTZ/+0LQxLnVe7gkaKzfxR0NGf46e5l6c3cm/Qj
qJJt2zwbvp0j4JMteTN44/+NZo6IcgA9/fUbEeKIq6+Tvp3mSA==
--0000000000006974eb063b5ebabd--
