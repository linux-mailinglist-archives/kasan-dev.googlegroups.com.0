Return-Path: <kasan-dev+bncBC6OLHHDVUOBBV6ZYONAMGQEU356JMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16BBB60576F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 08:38:17 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-131caeb598bsf9245325fac.12
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 23:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666247895; cv=pass;
        d=google.com; s=arc-20160816;
        b=ES4eZMGPnqpjj4UHI6IGMSantjx5hh65fTD3iKNQ2PJYNPe1EYw1hc2+G5vkTnnPZT
         KtBTrMKCYuebX1r53dE0Z8WqEDK+BU3LNhVKrRaFrP/vsMRQ5trdxmnf9RsEcF3INyZH
         6ldp7JyR887hpMAymONU51wsJXQ8fCkCRiqbbCo6jmuJvq2yEuWG6LrdKyoDDHg6M6aq
         WFBc29ycbONXOqinOyE+ByKSSCEmDSUgjQGCUjhfEI4v+8HrKghxghhTKyROa6ZR6Ua2
         fes+FjTOewMcm/FEcimDeRcxhU0Mu6+2JUapHwOwJ4sI0tppgFc+aC5333KtGAynooaV
         VWtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e3PutI96jYAZnn2+F/b8u7n3WqXCksHZIGWlkzTQ66c=;
        b=s2FfQMc+nI/+Bjg9BJUu9RWOttzTtIBiTNnEWs0/rUBkPMNhNg6BejdtVStHwR4h8V
         4nGKre+KmzCNQEPmEGIfswL7H0o8RtrSQFFzcN9sG8A9BATtLDueCqU4uy995bwwZ5Zo
         z+6yN1xng58KQgLHJSHlSs9x3Ap3DEtTF7kvO3CEMLwd3z6bATI1uBqXkS16+DKA9Zc5
         EXxca/tiz/zp9BbuM8jsM4MD5sLPc3kIjaPFSWvXQ4qd5KubDnw7MMjO8xlYca4zFpWm
         BIwHpGMlhyuHrIltP7ljwkDD/8v5e1xR4eUsqkI40Xne6GRe69a3a7NWLLcDdH6QADUQ
         s5MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Vy3C1q7W;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e3PutI96jYAZnn2+F/b8u7n3WqXCksHZIGWlkzTQ66c=;
        b=XCc53t9v05gaKSrhFwHB5nSYbzeSxmG9crmPiOexhFWVfzT5uUwuhltjRXb10yk3/k
         SykV3ZFRrUVF89XLAHiVYPfJov4OixQsb0KhxOU73dkW5lhJY4ZXs0YnzLkOoFImpIa2
         rtASvehoLTWobLgvvKH2cIijUD85cvZuFPm0reIRC4oTj5LBjJmwjHYTo/sPNUU3Vt5m
         JRRMzA3ZWaDIvzg/98ZuFeeJAposQ7qv1O+km1z4UC0cDxU5qAsrBpSIInLcLBaLUiLj
         FNuzxpIP4TjnN4eTwvkFiWT/Z3bt9+5cibQTyzjjkMgt8y4ThY8BcWfrVuF+dfluNZzj
         F64w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=e3PutI96jYAZnn2+F/b8u7n3WqXCksHZIGWlkzTQ66c=;
        b=raBA9qtLj6NsbXVhO2TWVS1DwsMn5GObQN8aV/3zxnmH9wLrNH0hHK7uD9ujO8EY0S
         QS7YSxon8QDdnOeE8KJPOsiIGWVvzSKbQ20HM9JQ2V0E4awTxT40NuzRlHEsMBJZYyMR
         WLA3kveJxDbMRnIDlDE1p5DvQm11ZU4BuUZPRzoMCdpXqOhkf9MsuqCh6mYLTxOM07iU
         QHQ/TKY/da5ABikCTUqU082Yoq5O7omW/bX8Fsob1Z76/87+DopDxp1q8Ejs5WBWGHpr
         HqjdiL783EAoR4gfUnq+/x1FZIYpvP1QqXzINuUjxzzeiEX770Cw8dnvtn42jVHG+ppb
         TVlg==
X-Gm-Message-State: ACrzQf1iAqnvdYZPU+s5tHKJUOpgQmIiuIZwWTyOaKKYLjtEbAhk7z8S
	X/5MZ0oLJpxLisNYyJrmFIM=
X-Google-Smtp-Source: AMsMyM7dA8EkoMmSfksyUfEp7n42lJD3vLHopMIgBfrwwNDuNw9ClstFliiquLrLJ1mc+TvZtpMvGg==
X-Received: by 2002:a05:6808:152c:b0:355:2778:cbea with SMTP id u44-20020a056808152c00b003552778cbeamr13013735oiw.289.1666247895655;
        Wed, 19 Oct 2022 23:38:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1b0c:b0:354:e8d7:5fac with SMTP id
 bx12-20020a0568081b0c00b00354e8d75facls1141213oib.7.-pod-prod-gmail; Wed, 19
 Oct 2022 23:38:15 -0700 (PDT)
X-Received: by 2002:a05:6808:1986:b0:355:3525:8fb with SMTP id bj6-20020a056808198600b00355352508fbmr6574568oib.3.1666247895193;
        Wed, 19 Oct 2022 23:38:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666247895; cv=none;
        d=google.com; s=arc-20160816;
        b=Myl6xX0XQbRHzjmZFuYTXUXmHlEiCn8kBp8HXQTDOYo1xKQuqAzZLXII6/N9ZQhZRK
         jqIzBvQRran3WwqPvgCJSUWu84ZS+2iQjxRQhTyDdPpt3RYIyYzsmuvtSoHOsDPL1m7N
         vcPqR8K0oedcb14bysVIcfI1Iz+/U7E7blM5ePNO9UrjvYPO/pyKC74LKz+hoMPn/740
         ID6pca4w+kZPhStEqdvNnvo6niK6V++QjLLLM05PyBQyjcqsQCD92GdlotvCX5IxwMG0
         eFK0+ppov3EepO3SkXDPIXBJ39fKToX0mKpoyspaAXQ6dsE6VK6ETRE1fpfWoc0QXV4v
         ch/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OJwtZIhiXHFa/eK6+uIbFgKIw1pNsCj78PR1TNw8HGE=;
        b=ERRYvWJ7Srr3qsmP7m+kmpSn12EU0119c4bCP1JUvt0VhvPUw16qmsIDXr2wicEYBO
         /UyE/pQVRbIjkjZisvQumZbXpn4l7XOXDeoKm/mLQKKrQasKIfH6dkHQI/Sh12dA8AYc
         On29d5lXOvE7NdUW2ZMF5CCZ4UOD/664VJz5GQtTWqPdL1ZVRF/9wujxzYvFhuFy6Am0
         e4lXEbOWYC7TipJIPJqhY/L5ySyAvrA72MPfndbWUY/hIbbyE365dwo6XRZIEfoljTbu
         z3G30D5rjQrKbpI3W6QzEFmChMFUkl3Je+BKRAIWJIrvWwOeS9w0vkx5yJrBuxJkIDfk
         hEHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Vy3C1q7W;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe30.google.com (mail-vs1-xe30.google.com. [2607:f8b0:4864:20::e30])
        by gmr-mx.google.com with ESMTPS id u8-20020a056871008800b0013191afecb8si1036512oaa.2.2022.10.19.23.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 23:38:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::e30 as permitted sender) client-ip=2607:f8b0:4864:20::e30;
Received: by mail-vs1-xe30.google.com with SMTP id s28so3620512vsr.10
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 23:38:15 -0700 (PDT)
X-Received: by 2002:a05:6102:284a:b0:3a7:ce5:ca83 with SMTP id
 az10-20020a056102284a00b003a70ce5ca83mr5880849vsb.38.1666247894600; Wed, 19
 Oct 2022 23:38:14 -0700 (PDT)
MIME-Version: 1.0
References: <20221019085747.3810920-1-davidgow@google.com> <CA+fCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g@mail.gmail.com>
 <CABVgOSmP1A4d_-SNrWg7VruxpKj3SZz=Bzb2Xebd=EXw1imXyA@mail.gmail.com> <CA+fCnZcea7UrA11HyRB80WgrUXMtEkK0AjdxEN=H-pMuWBhQyQ@mail.gmail.com>
In-Reply-To: <CA+fCnZcea7UrA11HyRB80WgrUXMtEkK0AjdxEN=H-pMuWBhQyQ@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Oct 2022 14:38:02 +0800
Message-ID: <CABVgOSnC3Y4Dq4evkghiKpDYSe_kSeCQPo6193H0_WxQyx0EFg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Enable KUnit integration whenever CONFIG_KUNIT is enabled
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000e22e4605eb719175"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Vy3C1q7W;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::e30
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

--000000000000e22e4605eb719175
Content-Type: text/plain; charset="UTF-8"

On Thu, Oct 20, 2022 at 3:48 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Oct 19, 2022 at 5:06 PM David Gow <davidgow@google.com> wrote:
> >
> > > How does KUnit detect a KASAN failure for other tests than the KASAN
> > > ones? I thought this was only implemented for KASAN tests. At least, I
> > > don't see any code querying kunit_kasan_status outside of KASAN tests.
> >
> > Yeah, there aren't any other tests which set up a "kasan_status"
> > resource to expect specific failures, but we still want the fallback
> > call to kunit_set_failure() so that any test which causes a KASAN
> > report will fail:
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/report.c#n130
>
> Ah, right. Thanks for the explanation!
>
> > > I'm currently switching KASAN tests from using KUnit resources to
> > > console tracepoints [1], and those patches will be in conflict with
> > > yours.
> >
> > Ah, sorry -- I'd seen these go past, and totally forgot about them! I
> > think all we really want to keep is the ability to fail tests if a
> > KASAN report occurs. The tricky bit is then disabling that for the
> > KASAN tests, so that they can have "expected" failures.
>
> I wonder what's the best solution to support this, assuming KASAN
> tests are switched to using tracepoints... I guess we could still keep
> the per-task KUnit flag, and only use it for non-KASAN tests. However,
> they will still suffer from the same issue tracepoints solve for KASAN
> tests: if a bug is triggered in a context other than the current task,
> the test will succeed.

Yeah: I'm not sure what the perfect solution here is. Ideally, we'd
have some good way to get the current test, which would work even in
workqueues, rcu, etc. This affects more than just KASAN: there are
quite a few different places where getting "the current test" is
important. One option is just to use a global: we don't support
running multiple simultaneous KUnit tests at all, at the moment. But,
equally, it increases the possibility of false-positives if something
non-test related needs to access the test structure. This is probably
not too much of a problem for KASAN, but the function redirection
features we're working on benefit quite a bit from those redirections
not being enabled outside of the test.

Thus far, we've just sort-of accepted that these don't work with tests
which push work to other tasks, but it is sub-optimal. And even if
KASAN moves to tracepoints, this problem doesn't totally go away, as
you still need some way to know you're in the KASAN test to disable
the "fail-test-on-KASAN-report" behaviour. I guess that could be some
global flag triggered from the suite_init / suite_exit for the KASAN
test, though.

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnC3Y4Dq4evkghiKpDYSe_kSeCQPo6193H0_WxQyx0EFg%40mail.gmail.com.

--000000000000e22e4605eb719175
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
z/tQRXr3iPeVmZCr7nttMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAx+EQjLATc/sze
VoZkH7OLz+/no1+y31x4BQ3wjW7lKfay9DAAVym896b7ECttSo95GEvS7pYMikzud57WypK7Bjpi
ep8YLarLRDrvyyvBuYtyDrIewkuASHtV1oy5E6QZZe2VOxMm6e2oJnFFjbflot4A08D3SwqDwV0i
OOYwT0BUtHYR/3903Dmdx5Alq+NDvUHDjozgo0f6oIkwDXT3yBV36utQ/jFisd36C8RD5mM+NFpu
3aqLXARRbKtxw29ErCwulof2dcAonG7cd5j+gmS84sLhKU+BhL1OQVXnJ5tj7xZ5Ri5I23brcwk0
lk/gWqfgs3ppT9Xk7zVit9q8MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCAo
ogmkt0T1uj2QIKsXwG+hFNXz6di6nxMeYsddbR3IzzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjEwMjAwNjM4MTRaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAjoQr8agQ2/ydqc4OA2Oc
drTCyCW0z5RqDAjvLJ5Or0Ng6s215FH/WgaF0Vu1zx+wntJ9B5P/s5rFUmgSc+t7yvBAfZPbItxd
MU86verb4K5Dx1NNtxqJnUrQcuZt1uyenYinVhnMFmj4HJ1mVx+FP3A4V4mIuZsKFyrUGZYWzR6A
m/ZrnCBogOxKiuqFJ2NcW67pg4lmHi2DWuoGjHdwCSabVdw+fm2JysegKPieAJjnGHeDQTBsyE5f
xnHt84ns4MWo+viXnr+/dGvfk8b7+bP6zU90/izWoTzbC3olb6pISXPlOSwvPC7DTHRE9bviMhQ6
zyYIRHwF5ias8cmwLg==
--000000000000e22e4605eb719175--
