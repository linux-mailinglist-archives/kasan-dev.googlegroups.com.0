Return-Path: <kasan-dev+bncBC6OLHHDVUOBBQ6FUKJQMGQEWTN5KPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 27EC2510E4E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 03:56:20 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id o11-20020a2e90cb000000b0024f24265fcfsf212856ljg.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:56:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651024579; cv=pass;
        d=google.com; s=arc-20160816;
        b=0NtUYRv3I6FHeuk+zSy3EWtzfTxz7z/XHNtnDEduz7iPlE7H+24Ub7zuMBrKY/FXod
         Dj4Q84ePfeRJ6TluI39MGZxzTJdxzXaeJ/YL1vxoTB7Pap0WMsxCnZBe52+HPMoL7/LR
         gQIGatzxrJ6uOWh+ImEWIldoa1u1Z7/f8XqyEdfmldKv1G2IU/Gxljn7o/PZT1cFWLnJ
         E2DZKQ5SN6x+7Ovv7YZ0+fTwoH9G83pGWLXtV9b5ZMCs/xGZpRwhWUFk4859Kif+PCTQ
         QkSg4UQ+OVdqqMbGRRQgpw5tf9uhHTZgo7FFhzbm3SWjcGTWNxXE6DZ7kDPhzUDTQWyL
         6QAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yvKMjRqBTd2BbjXjgxg9Knz+/xwWyDE0ggFSauwvRpc=;
        b=EzAoeArGzeGZ5Zii91LmGM/YLRdsFrR9b+YZW/Ktz/Ozi/kGYSuOF67Usp6aR/azPE
         orhMtPXzb1d+YWL5YbCvUnY3heydTNBrZNZ1EQVdWdo8uIfaQ+Dyz5SP8lzsjOgpHrPn
         4KA5tuD74gPYMmO/BkqodTshlFUfXic+lqKkczV3XI3F0EHM4HgXHEIH/zMWwXvIAl+5
         X6eCUJtbdjKXtXJJ7HvoOtS88OQssDSKgQZuXXA0I4VIFMKhmpRTSTH47aCwbcIdjJxo
         RrateWRZKrqjnY26+cROUwfl04HUS2R7a+2TFxy8ECWxYxycmGuIeaiwLQCitVx0CVPh
         Niew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RrmSn9Ri;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yvKMjRqBTd2BbjXjgxg9Knz+/xwWyDE0ggFSauwvRpc=;
        b=etMFBKD50W5T+mXRPnQ1f/mE3eGaytbFOlranX9Y2XIzI4+ozT1zhcm9iFGRB7KcZY
         3+IKD0Y+HXI3gHboHlpHJ+2PRsWBlF95p40q01PL5d90Q7gHXFDGFFpRGx5+QguOYMkL
         kl33/4YXzeLmqbcW7i1Z1aD2I3kuEu/pH/u9RYiLuC+FSnw27U9zSg+PbTzQ+pfsx6AP
         Ugyy/mh2jGWI4GXCTu4SkaiLdLLdpgriBivA+wQa06lbWCGksWhTRBEOaB9OE2cVlNsq
         aNOvpfN2XBOtQY9UN67p3eytj9szslW1wz+9DtJDmWgDd+BIVWSGJlt7T5ubA0wxtLYq
         Q8uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yvKMjRqBTd2BbjXjgxg9Knz+/xwWyDE0ggFSauwvRpc=;
        b=detbkS2AnP1Cl7ELZ/Fay77KJXW/5Uue/a4Rk/fZdvOHnCYwm/zauGjfwrv1jNN02u
         fAnIn/EHCsLiSN0oSv+f5Zz/wAb7/X/Txd+R0VjBVXzNYWdxRE+v2RG9eddnWpUpH4sQ
         /aNvjyT7p+M1oKgbBBJBWPK2zVZdDgnRoSkKOG18B9V7gFpfHEt4r3Ng+NDWHuAQvD9l
         /oxTthiZ6xMGeI1kMXeA4HC3r659ZW9tesIBZYFxM8Hr0/T80Ne2948P4PloNKzBWB+1
         VZIFknUHTwlGxG4cODdprDbu5O4aIj0YCg4WriSHdzCpDHAjd4wwm8bWnojq+IDqd3iY
         o40g==
X-Gm-Message-State: AOAM532xXTm6wevH57HYgwN2uPQEoUSa+SRA9BbvmDbwW709EQybuy5J
	RGnAIk1H7ogUK+TvoETIzWo=
X-Google-Smtp-Source: ABdhPJwEGHOojMjhMkkxcIdMIy66ooC+8MxrNp8hfNyhRRcaMuTDMVhDGD64u/yeZfaU2EQJYjs18w==
X-Received: by 2002:a2e:aa8d:0:b0:24f:d2a:bc0d with SMTP id bj13-20020a2eaa8d000000b0024f0d2abc0dmr10293680ljb.274.1651024579495;
        Tue, 26 Apr 2022 18:56:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:17a4:b0:24d:5627:cbb7 with SMTP id
 bn36-20020a05651c17a400b0024d5627cbb7ls2430782ljb.0.gmail; Tue, 26 Apr 2022
 18:56:18 -0700 (PDT)
X-Received: by 2002:a2e:9953:0:b0:24f:2926:6a23 with SMTP id r19-20020a2e9953000000b0024f29266a23mr725131ljj.312.1651024578129;
        Tue, 26 Apr 2022 18:56:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651024578; cv=none;
        d=google.com; s=arc-20160816;
        b=iz7HporUK4HeATM9J6R43Q6oRSsB6wuBqQ2aRv2xeajXVXV1nCX9h/+ZaSYjm8bfVh
         iiBYWyqMGgvlL4ztqIc1ufQLwOoJgKXfQFUUPi2zfVoEie4CMqDP4jOgest7VxhS5tIV
         79/oF/yO55pyo2dJWjS4TWUP7C8s1gbB4ZedMlJcDPIVseEfrXUUP1odDonuCJ813vBs
         3ORVDvqAsUsskSAguVdDicZlNXXfhXccSRhaMvJAyvNXV8vpLTctzINY8SXYiPLf9sKR
         U4/a8THJAZ8qqKu6FJAcfDyS3KGcwDU3JYof1fl+fV4pWuD7JzY1iycsUPQvmZ9TBXzD
         wFDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4+RoRptIoqwVI++YuI9oIIgcpfAnL+89GXQ7Eys5BBU=;
        b=NkIC/wyLjEi4EtDW6C6PszqBlde8LGmpE3cMR7zK15gobUxVVbBHtCDRD9krHvhw7s
         QSGk6/UA8YppPuukIeqKqpVlbUICyd+mVsERESHscYLDtd07FxahSOMbTh9d87cqR98V
         9UVpdPMeILB4sTuA2ZKxB075EqrIgYs84lf8cFDffFH2Nqurlf0cm4SL0Yeswsl54wba
         bI8sfjZ/c7OhCb1fcquBdWwEoc7AEAZYjBfgE5nnV/LSWGeqOBwPLbny/59YqFcqUosa
         nANV3GYtOZrHkVDx7Vo0gjwXWWitjhqr65sXqgDm6+GcPNt/y5xIoEwVPZofraOfqLqq
         xJ5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RrmSn9Ri;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id l24-20020a2e8698000000b0024e33a076e7si13318lji.2.2022.04.26.18.56.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 18:56:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id s21so473804wrb.8
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 18:56:18 -0700 (PDT)
X-Received: by 2002:a5d:6b0e:0:b0:20a:dd17:e452 with SMTP id
 v14-20020a5d6b0e000000b0020add17e452mr9372396wrw.501.1651024577517; Tue, 26
 Apr 2022 18:56:17 -0700 (PDT)
MIME-Version: 1.0
References: <20220426181925.3940286-1-dlatypov@google.com> <20220426181925.3940286-3-dlatypov@google.com>
In-Reply-To: <20220426181925.3940286-3-dlatypov@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 Apr 2022 09:56:06 +0800
Message-ID: <CABVgOSnU+jQsd_eUvSc1+gpcW3su0W4ZEHUc6kj9zu3nxFVXsQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] kfence: test: use new suite_{init/exit} support, add .kunitconfig
To: Daniel Latypov <dlatypov@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000079775e05dd991db9"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RrmSn9Ri;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

--00000000000079775e05dd991db9
Content-Type: text/plain; charset="UTF-8"

On Wed, Apr 27, 2022 at 2:19 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> Currently, the kfence test suite could not run via "normal" means since
> KUnit didn't support per-suite setup/teardown. So it manually called
> internal kunit functions to run itself.
> This has some downsides, like missing TAP headers => can't use kunit.py
> to run or even parse the test results (w/o tweaks).
>
> Use the newly added support and convert it over, adding a .kunitconfig
> so it's even easier to run from kunit.py.
>
> People can now run the test via
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=mm/kfence --arch=x86_64
> ...
> [11:02:32] Testing complete. Passed: 23, Failed: 0, Crashed: 0, Skipped: 2, Errors: 0
> [11:02:32] Elapsed time: 43.562s total, 0.003s configuring, 9.268s building, 34.281s running
>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Daniel Latypov <dlatypov@google.com>
> ---

This works for me: I'm very excited to see these tests run more nicely
with kunit_tool (and not break the TAP headers).

I guess the next one to tackle will be the Thunderbolt tests, though
those are more complicated still and need some module changes, IIRC.

Tested-by: David Gow <davidgow@google.com>

Cheers,
-- David


>  mm/kfence/.kunitconfig  |  6 ++++++
>  mm/kfence/kfence_test.c | 31 +++++++++++++------------------
>  2 files changed, 19 insertions(+), 18 deletions(-)
>  create mode 100644 mm/kfence/.kunitconfig
>
> diff --git a/mm/kfence/.kunitconfig b/mm/kfence/.kunitconfig
> new file mode 100644
> index 000000000000..f3d65e939bfa
> --- /dev/null
> +++ b/mm/kfence/.kunitconfig
> @@ -0,0 +1,6 @@
> +CONFIG_KUNIT=y
> +CONFIG_KFENCE=y
> +CONFIG_KFENCE_KUNIT_TEST=y
> +
> +# Additional dependencies.
> +CONFIG_FTRACE=y
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 1b50f70a4c0f..96206a4ee9ab 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -826,14 +826,6 @@ static void test_exit(struct kunit *test)
>         test_cache_destroy();
>  }
>
> -static struct kunit_suite kfence_test_suite = {
> -       .name = "kfence",
> -       .test_cases = kfence_test_cases,
> -       .init = test_init,
> -       .exit = test_exit,
> -};
> -static struct kunit_suite *kfence_test_suites[] = { &kfence_test_suite, NULL };
> -
>  static void register_tracepoints(struct tracepoint *tp, void *ignore)
>  {
>         check_trace_callback_type_console(probe_console);
> @@ -847,11 +839,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
>                 tracepoint_probe_unregister(tp, probe_console, NULL);
>  }
>
> -/*
> - * We only want to do tracepoints setup and teardown once, therefore we have to
> - * customize the init and exit functions and cannot rely on kunit_test_suite().
> - */
> -static int __init kfence_test_init(void)
> +static int kfence_suite_init(struct kunit_suite *suite)
>  {
>         /*
>          * Because we want to be able to build the test as a module, we need to
> @@ -859,18 +847,25 @@ static int __init kfence_test_init(void)
>          * won't work here.
>          */
>         for_each_kernel_tracepoint(register_tracepoints, NULL);
> -       return __kunit_test_suites_init(kfence_test_suites);
> +       return 0;
>  }
>
> -static void kfence_test_exit(void)
> +static void kfence_suite_exit(struct kunit_suite *suite)
>  {
> -       __kunit_test_suites_exit(kfence_test_suites);
>         for_each_kernel_tracepoint(unregister_tracepoints, NULL);
>         tracepoint_synchronize_unregister();
>  }
>
> -late_initcall_sync(kfence_test_init);
> -module_exit(kfence_test_exit);
> +static struct kunit_suite kfence_test_suite = {
> +       .name = "kfence",
> +       .test_cases = kfence_test_cases,
> +       .init = test_init,
> +       .exit = test_exit,
> +       .suite_init = kfence_suite_init,
> +       .suite_exit = kfence_suite_exit,
> +};
> +
> +kunit_test_suites(&kfence_test_suite);
>
>  MODULE_LICENSE("GPL v2");
>  MODULE_AUTHOR("Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>");
> --
> 2.36.0.rc2.479.g8af0fa9b8e-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnU%2BjQsd_eUvSc1%2BgpcW3su0W4ZEHUc6kj9zu3nxFVXsQ%40mail.gmail.com.

--00000000000079775e05dd991db9
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIPnwYJKoZIhvcNAQcCoIIPkDCCD4wCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggz5MIIEtjCCA56gAwIBAgIQeAMYYHb81ngUVR0WyMTzqzANBgkqhkiG9w0BAQsFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0yOTAzMTgwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFIzIFNNSU1FIENBIDIwMjAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvLe9xPU9W
dpiHLAvX7kFnaFZPuJLey7LYaMO8P/xSngB9IN73mVc7YiLov12Fekdtn5kL8PjmDBEvTYmWsuQS
6VBo3vdlqqXZ0M9eMkjcKqijrmDRleudEoPDzTumwQ18VB/3I+vbN039HIaRQ5x+NHGiPHVfk6Rx
c6KAbYceyeqqfuJEcq23vhTdium/Bf5hHqYUhuJwnBQ+dAUcFndUKMJrth6lHeoifkbw2bv81zxJ
I9cvIy516+oUekqiSFGfzAqByv41OrgLV4fLGCDH3yRh1tj7EtV3l2TngqtrDLUs5R+sWIItPa/4
AJXB1Q3nGNl2tNjVpcSn0uJ7aFPbAgMBAAGjggGKMIIBhjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l
BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHzM
CmjXouseLHIb0c1dlW+N+/JjMB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHsGCCsG
AQUFBwEBBG8wbTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
MzA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvcm9vdC1y
My5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIz
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
G7p3AiuB2sgfq6cOpbO5MEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBsL34EJkCtu9Nu
2+R6l1Qzno5Gl+N2Cm6/YLujukDGYa1JW27txXiilR9dGP7yl60HYyG2Exd5i6fiLDlaNEw0SqzE
dw9ZSIak3Qvm2UybR8zcnB0deCUiwahqh7ZncEPlhnPpB08ETEUtwBEqCEnndNEkIN67yz4kniCZ
jZstNF/BUnI3864fATiXSbnNqBwlJS3YkoaCTpbI9qNTrf5VIvnbryT69xJ6f25yfmxrXNJJe5OG
ncB34Cwnb7xQyk+uRLZ465yUBkbjk9pC/yamL0O7SOGYUclrQl2c5zzGuVBD84YcQGDOK6gSPj6w
QuBfOooZPOyZZZ8AMih7J980MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCDO
B+2p8LLkQs8XALT+pvPloHN5teI7hKLr37YFvIcy1jAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA0MjcwMTU2MTdaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAQehjir8ainkO9PiRhFTB
d7pj/NLqEQ+6a5zqBWova8H7VLjB4GAw93OGlMv62Ln6FDiQq/jRu55BpU3f3f4QNmQSvp1x84Cp
6IUlen8I9e+LyVZZbyG7CILw6vfuWBysR7faMT5Zr1bQQAmPNkYTReNlmWYihoSUh6vn2vgI3eHs
PrZ7aoUt6chBtqMVJoTF+qTKBJmkT7tuixtIl1c9DQFk+7Sea37L1ZkXufflcVrN7No32ESeMi1C
Ycz8kWaFFw/xdS/lNa7EDqP1da9CtDKDFJjUBaNpFsTZtc+GXaP7pUihh7nRzdfy0UhfZsBtJwjq
+9tSbAJxuUc+bDHITQ==
--00000000000079775e05dd991db9--
