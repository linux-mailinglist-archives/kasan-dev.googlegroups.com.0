Return-Path: <kasan-dev+bncBCUNXXPATEBRBOG7V7DQMGQEHOQDO2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DBA4BD099F
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Oct 2025 20:13:14 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-29053c82f8fsf39448535ad.2
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Oct 2025 11:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760292793; cv=pass;
        d=google.com; s=arc-20240605;
        b=XjDCmsUf+Iuo00lqdJHYUxrmASTDgP3SgpHXzqSB4EJ7aimVWXOrFIfQ7MirdloUSe
         hodML2+IcATy0pUSC1ACJVN1ukBqRhupk1x34VpAzDaGjYFG1pXpWKb1RDNFc+aI1nB8
         RMqopAUZaClROXstIM9/d4PFl0wXVq6g1HdDc4afpRwYJF2YeIrAbx43PPwno5105YQi
         fwuApTRBugGlaW9DvEotdVtdFLzl3zv+CYlj127MKf+1R83jQIso/en7QcpqHrXT9eHy
         Nn94tSB1rTnbORaEMNAv56ed+hQg3Q4EFUN07Az82hy4R0YdMPsvpxohgmrQ/rdXPe8u
         KqRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=xNkcddW+CztimpA+OdAMJd81k/5jyOFIaOdBe/ZOU6I=;
        fh=8UmMEwQ1CSk19l27+loZ8jmCn8Pm01q5aFXrGE6w3E4=;
        b=eWXgkRxrZJ08sUX7OGLD7Z0D/6UCaZHHOOBe8FtujLsPoZgIaTY/DOOLNZOXKo0vSs
         H7hLjoxBm7x2KHNHtm6WBVY0kp8tIT3h48tj/yfoqAsMTHaU6hrwjtW7PzO0eCL0HCa9
         WGRNu3PrVDdy7nn0MZh8PMP1ugr6dZnUI72mpqrq77/qGh81ml0bsboh9HYnmdmt/CfK
         puI8PxRM0LMb2ys0sV5YnHlJpdA4Kk8BocQA4/m5GjZmSk5ueHz13yk+nB5SbuMcsRwu
         U6J4wvXnW6/0NepK2Jw8fsYtVMTOLu8lDsVOPTLpMridqJTLEN6mzEGRoaybhmktU+dn
         +C9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KsZt7oVr;
       spf=pass (google.com: domain of koblak096@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=koblak096@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760292793; x=1760897593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xNkcddW+CztimpA+OdAMJd81k/5jyOFIaOdBe/ZOU6I=;
        b=XoPKSVI/rR8e5oaiRG965R21ytFU0B1D6VkVIrmUrKHb5yXasNOmivxFjual66cmIm
         uIF2uDf1O9OMotxdpQwQSSVZl/kVeTOw0SPgiLhgOcLBvsYdOkMpXPmtJISjZzwsRkjX
         fUxffRfSjztFdV7a+mYEV/Kf4Yy3cwwIJoOao1JveN1ZFiytxpQpfpAzuEN3g4HOSaFX
         E1sI9q15V7dVGg3lvi8pqfj52/ua3FmFt/jBA7Px+DLfg0WI52zyYMHw+RXHtaiOsHa5
         GgPUXCL4eP6GkakV0/+9vyVAHvIHU4+MnyswQsLsNvR5QzD4+CtpF4c6MBoWHKssMb1G
         hleA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760292793; x=1760897593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=xNkcddW+CztimpA+OdAMJd81k/5jyOFIaOdBe/ZOU6I=;
        b=AbRuOirVOydU5T7E1zxQK7TjfAVPzbB+Oj/VXGJKJ1IsyFTotsJaTFTLdZYYFONWJI
         lR0/z93R9R1O1jDM2qumAz0Ng0NKJ0c0cV35n+j2LUBI5VGQj6rpoPuF2sLsfTcJsLMo
         fV97awSNIVrpREmUIZu2DMo1ZyMV22iC86dK4zsJK5E6udYqJ94dwTTygKZblx13R3rP
         H6V/ogpPFMrJk2gZfI1C58DKKQM7m+169V5nfCrA29lL3k6zSINP0Q8qZNpCfZa9bsJd
         Drq+87gaZdY0wsgFbQ0a0KVImnGPPn53+3tKA+Otrsq+73OtgKGmmBunlR/ezSxbnIyJ
         dLKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760292793; x=1760897593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xNkcddW+CztimpA+OdAMJd81k/5jyOFIaOdBe/ZOU6I=;
        b=UjN283RKycejriSWQqHRgY9dMgx9GU7fUbaCd7CZa56Bfsr45c7YUAfaJ06TqS3flq
         5yyZU0lMp1rU7TW8lH92UUGpGADHW+YO5Ert5rle2k9/4AFr1oqH5hP/L+q5YtTzICFp
         dawyvMvLBm8AzYfW8ZlVJQRJ88q8RDxKy2owCGnuSAUKkbM4eVYJrDehIk3hjHEqHmyF
         j2A4LVp8wSXZ0ZCKpVV542ynN3qBCThNj97kk6ZsF5chNq9PUSEcVKYmru1kaD+/dmG+
         YixFmMeSdJd8tSELC+MnTnmmIbg57YbRXmX57QSAkzMOynhXLBnlfn86ZzrQifHRc36t
         Jgzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVew86l+/wXezYf+zmB0EZgXNVzSUtIVWAwoUSXWe4JCxXdD59COg+aO3lxcgUztLz32dPH0A==@lfdr.de
X-Gm-Message-State: AOJu0Yy7rvwyIbWymrRxddee2PXzAgUtTDH79uVMALtkjwl5QZp8lLhs
	gOn7bRXoqWAR4Rg9CDVtywnXbkzC55EZ+UeVovc0400o7a9mISYWpDbS
X-Google-Smtp-Source: AGHT+IGcxi9Xl05aRIRcUM32UOoGlMahf7wW6CWFHY81o7XggDQ5r7s6EVJkOi19ajfZS7UQhAo1Ag==
X-Received: by 2002:a17:903:1aee:b0:264:ee2:c3f5 with SMTP id d9443c01a7336-2902723bc78mr254950165ad.19.1760292792515;
        Sun, 12 Oct 2025 11:13:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4W9Lzt7yyiGlznlXWuszSTcIqntjFGrWHaFHJ/5izGNw=="
Received: by 2002:a17:902:7609:b0:269:6ca9:a91d with SMTP id
 d9443c01a7336-290357bd9b9ls30008705ad.2.-pod-prod-01-us; Sun, 12 Oct 2025
 11:13:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7zn/9Q0SJHzFjsUrIT9CYG3kZeSRJH7ufZeYKIghDl4l8Y2bUCga42UHSsEHpedRoZ+PnvTjCKpc=@googlegroups.com
X-Received: by 2002:a17:903:2c6:b0:28d:18d3:46cb with SMTP id d9443c01a7336-2902723bc8emr232896505ad.20.1760292791169;
        Sun, 12 Oct 2025 11:13:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760292791; cv=none;
        d=google.com; s=arc-20240605;
        b=K6sCnSyOGyiRGlYM/GK41M7inco6/FFp6eP8d+ojRryeeV5/cWQfDWfhmNdpxn4Cc5
         bWVqb+k3hLXzw7Vh8WAWC2oidyq4gkYFGsbxjYmHG7qGwFCQ55HkJSJI4IO0JMilfW2t
         lAU+tqExiEh7d84ed3BwHxDmoWRmbdNRiHrj74U+fsGgUlLPSHU45XMIYg4aIYY+MmPd
         59xM3oKbdvLNhcPzZPj9WMLD7HLzyFftbylIK04SzTyBNbqUZMMg/qgfcn2fEBnmRrfL
         2/gQ9i7bmcPssy+e6sawxvOY94bxqVNMDQDgp/HIRXM8+KG/TYFLgppAvpWh7kVLz5Tf
         da1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=C0G9x5Cu3FOFyoZeOB/LzYQjnN+AvsDfiZRgPdHDNyM=;
        fh=Tot0aQOIwvsH5df7vMFu0D80HyX4fkgEtHbqEM16sHg=;
        b=bXjsJTpVGZXKIauukt0qTiQQdTINEzfWTcbeL2sXhMlMHqsXGDhaheT6rlkGWo2oKb
         Pn1iexV8O4ynjQJW2IfMXKQsjN1oaJAijJ0hIOr5r82JI70p47zN9zdlyDQUO6eB8UbR
         LzABe3Vn4XNNTqQNG4qN11tIbNVneN/PjDicPVCjoZzdbRjUIfJ4q6c7iyNp7aAmreqc
         sqs89RcXGUUUleuxA89gP65nddEFaBvdZkER0bvO8vUkKU04uyBKrBJpvGCmc8wjTqje
         ThsMSZaOdYVctwcBPi6TX7+yt0aMGUuvzaSPuALROxN9a/qrIhEe5uNAfEpS3U0+/dXs
         H5DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KsZt7oVr;
       spf=pass (google.com: domain of koblak096@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=koblak096@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29053854083si4006805ad.6.2025.10.12.11.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 12 Oct 2025 11:13:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of koblak096@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-2681660d604so39186205ad.0
        for <kasan-dev@googlegroups.com>; Sun, 12 Oct 2025 11:13:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXhBOAX8PiBp4g9IwWVF5D/0ctXOGRQ8cfwUqJ2GT0te5ygouJl1ZTG3lvcERYWL8aZaJC0Ayu43P8=@googlegroups.com
X-Gm-Gg: ASbGnctmZoSX776QRzpf4CJmT7Ok5HNE9peNlm7A4ukBbO1uzPBiHak2H7r/DScKez+
	OA4c+FbkfOQd+9GTe45y1VJF5gzOW+5tmEinqXDlsUOVeHBNl8xeJtHU+nL6kd5zNXZAwJoY8/u
	9VIhPmGKZI2j+w7ytF4wjWKwefm5s2W/01clPWN/VYbAGIoF7UZsBWrnGlT/fttYZNRNR9z5ioW
	5oGEXKU+rb+X68bZSzY/07L8aTnu8rfk2VuLbDstByT8cvLmlJNbnAxyAPfjRwvqRdasK9g
X-Received: by 2002:a17:903:1a43:b0:24c:6125:390a with SMTP id
 d9443c01a7336-2902721357cmr221112625ad.10.1760292790562; Sun, 12 Oct 2025
 11:13:10 -0700 (PDT)
MIME-Version: 1.0
From: Kobla Kwaku <koblak096@gmail.com>
Date: Sun, 12 Oct 2025 18:14:59 +0000
X-Gm-Features: AS18NWDcIOEsZr2XiTo4yxzQyQcjWbm-nAf47FH_DHbQI8oajBYMD1Q-UEiFGL8
Message-ID: <CALSOvXpsnU-JeONpwiWz9CY2akk-tYjKL=WneTKXUPK+rVSQkw@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000007b742f0640fa1ad8"
X-Original-Sender: koblak096@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KsZt7oVr;       spf=pass
 (google.com: domain of koblak096@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=koblak096@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--0000000000007b742f0640fa1ad8
Content-Type: text/plain; charset="UTF-8"

Dear Sir,
I am Mr. Kobla Kwaku, Financial Consultant from Lome Togo. I want to
partner with you on a transaction worth $65M USD. I had a client who
unfortunately died of COVID-19 complications from 2020. I want you to
receive this money as a representative for my late client. He died
intestate together with his nominated next of kin unfortunately. I shall
provide to you all appropriate legal documents that will present you as a
legal representative and entitlement to this assets/estate. Part of this
estate is in AU METAL (100kg).

We shall discuss a whole lot of issues including disbursement modalities
and of course any questions you will have regarding the process of this
transaction in my next email message.

Best Regards
Mr. Kobla Kwaku

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CALSOvXpsnU-JeONpwiWz9CY2akk-tYjKL%3DWneTKXUPK%2BrVSQkw%40mail.gmail.com.

--0000000000007b742f0640fa1ad8
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Dear Sir,<br>I am Mr. Kobla Kwaku, Financial Consultant fr=
om Lome Togo. I want to partner with you on a transaction worth $65M USD. I=
 had a client who unfortunately died of COVID-19 complications from 2020. I=
 want you to receive this money as a representative for my late client. He =
died intestate together with his nominated next of kin unfortunately. I sha=
ll provide to you all appropriate legal documents that will present you as =
a legal representative and entitlement to this assets/estate. Part of this =
estate is in AU METAL (100kg).<br><br>We shall discuss a whole lot of issue=
s including disbursement modalities and of course any questions you will ha=
ve regarding the process of this transaction in my next email message.<br><=
br>Best Regards<br>Mr. Kobla Kwaku</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CALSOvXpsnU-JeONpwiWz9CY2akk-tYjKL%3DWneTKXUPK%2BrVSQkw%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CALSOvXpsnU-JeONpwiWz9CY2akk-tYjKL%3DWneTKXUPK%2BrVSQkw%40=
mail.gmail.com</a>.<br />

--0000000000007b742f0640fa1ad8--
