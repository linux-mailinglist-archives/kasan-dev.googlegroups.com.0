Return-Path: <kasan-dev+bncBDW2JDUY5AORBX6AXKXAMGQEO55HNJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96BC18571AA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:38:08 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-410727c32bdsf6981645e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:38:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708040288; cv=pass;
        d=google.com; s=arc-20160816;
        b=eUMnJtLbFLHxwU1FwS9SsGODw5DwNMV/yoXVgDByZznbTpwRf2THdGuUmimUoqPa8s
         owbDDKxcywCB3FSa8xI8VVmS5n3/fXJxK/6XwlJ/crOyqtxxJ1PJ8VD9emu38+Cbguiq
         XnMQXHHgq1V2R7Cmb1dJxxWdzHbYIzu2AwIHYRP92t2ztuaemx4U30bSmXaiTTmpCzPY
         uTWJ9lIV0tgw2Os9PZOpgyBbuWToe4y9C0q2CGs5ePcmyOT9VMb4aA6xHPMmrwk2lZ2j
         jXyjvjoBsBFJbRT7z8RE8d1htU0Q4x22Xo6CuKfdgRR4NJAErk7cX5ShL+aD2/IdZBdb
         Tviw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=E5NLow+zZX6GiGd9Kf+kpFoTJJqgzxsV073eCQMdTNM=;
        fh=yJk7hGjv9YmNcQLHgl6Mp7tnFd/50e2Uc3eXFog7ho4=;
        b=skf+aBPOfG1ZQQCoJdybiGWdcUYtl1Nc/GngyfMjQht8x6jUIFoF4mPqsYIGKTQjce
         GcoIIv9wDpVOZIRsqxNhNJ7Ux7aqiKnXNkY7B45pp6TOLZhJNsITZlaGyU9DXJYBt4CT
         K/gtGTUK0hV8ZOM5SXYp/8VGTwslFmucHrcW8Dnq1YR0F3llJ39RLzMrg2N249shRqBu
         NoUqcBCpmRrzuzg9uczNPdosjV+XhUdfsUgyhoWZ803iW94Rz3RKKUkRQIkxu18wUWOO
         ivQ3Y9XvBBszJAVEcx51qS1T3AVxW+nt7IbFD7AKYGn4o3ARTRNBRz5/f9s80uR4Jz9O
         WKdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cylmfuzQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708040288; x=1708645088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E5NLow+zZX6GiGd9Kf+kpFoTJJqgzxsV073eCQMdTNM=;
        b=FnkoJeMYMSh1RQBxj8MwykvDnBhnYerDzX+IK3nZT4jC+OGz07feqyX6/rh+bSw+8I
         Fz4ZdkMzmtjEUZ27nrpCG06eg1JW5BVgF7kTG+YeZGtQrv9PlIWSNn4cbAxyA9deXI5r
         LOG+hQm12Pmr6e5wqz8KOhpJ1k+r3VmQWfwBECA2P3wOzze+y4ejOFK8iXxeLNiG8ww3
         lhAt7oMzdWaV+uwhXsCPiojqSAPwGtAs2Ix+SvV7/qRHZuq+6M2mvkot/OO34msmQ4Og
         7uH+jRcTtE1y1FZKQOpUCMmDo0n1PLKOjH2IxLUcqWTe7gwMXSwQM0gopT8p2FaCMInT
         41iw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708040288; x=1708645088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E5NLow+zZX6GiGd9Kf+kpFoTJJqgzxsV073eCQMdTNM=;
        b=ZcnIewTPXVQQZAxvFbO3U5o/O451K5WMmRXDCFFiQH9s55kHI5Ouaci9kjnb0FBeWr
         SevvWg+kO+r6aLxLcY7tUoIhLnkiaWo0H/yqKyLJVpxUzhOvUeml7o8JVC4tnGVKNGKd
         BtCM41G/V0pFlSAOYfHRQbczwloxmeN8QIa7KI7SJGSWiPDUBG+JbLg7QYpRfUpPJQYz
         AqqbdyOG7QAwYpfnZDqlddQavFP20Fp8VUEkuGE7hf2lDOO+bCjGJYEGd05MFzddaJeb
         a7eNREmQ7amrocwI5YdCzBHL6D4tgEmuKh2hckIvo6vmHOBzW7URs/Xx/wU1ZLnfya1w
         g+WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708040288; x=1708645088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E5NLow+zZX6GiGd9Kf+kpFoTJJqgzxsV073eCQMdTNM=;
        b=iSF890GuJHYqk0BdRniSM6ah1yXtH7w7ug5pnr4l4YbRu8tL5YG7cIw6bZKZOhriHM
         78Qoc78dV513D/XRtIzuowC/KiIxLCdz8EjPIOvTqxmJnDMbdCo42xFbWuoxYz/m3Wwl
         /PWC5QoomES3py411RqehG2eMG1yeNDiuro4BauBSTdYCj3eYE48a+UOXdlhyK+IrFH6
         /MzLB9f05NGF2OJfccCC4/swNR1zwSr6N3a66tsFWdUdKIod6lhioY88GLn92TLOto0d
         xQM2Nd7/bXr1nq4aiuNdLFALO7fqbSlUqOC1WjGCeY27hTPs+MgWOhD+YAPbYR4owWB4
         Ecug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPtoukCMRioMMb9kw4U+M8z75LHpHGPHpsf7kbMpBUbPN+arxrDcqmY4qa7KwqBk2cazbr5iuVV2550IEcxw4H5rRhq28P9g==
X-Gm-Message-State: AOJu0Yxn7si1r17ICp0BDsdswIam+YkwE8fSoqe7RLmkJ2+cDrlcH4Wa
	pVgHEwUFpl176aSMriXLMuDMvYgcIS7D9OI0/RZYgMoXUIAqlYja
X-Google-Smtp-Source: AGHT+IGN02NO0q1ALLhFsQbNxLISYMysqQPYw9tPKIzAF2cde7X60n82hFoip/1XRDxM+ujMQoo8qg==
X-Received: by 2002:a05:600c:474c:b0:412:536:c24f with SMTP id w12-20020a05600c474c00b004120536c24fmr2239957wmo.2.1708040287721;
        Thu, 15 Feb 2024 15:38:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:a001:b0:412:955:8f82 with SMTP id
 jg1-20020a05600ca00100b0041209558f82ls129144wmb.2.-pod-prod-02-eu; Thu, 15
 Feb 2024 15:38:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUPAznlbdVrYTWoj3mb5tCdn7djr1A6RELz6tqLGPXnoy7hxiqa96eDXteGwYjTMbGcZKrfAjZuxuUh6OUIUqFMCJrvhRdinG1/zg==
X-Received: by 2002:adf:e80c:0:b0:33c:2e8a:ddee with SMTP id o12-20020adfe80c000000b0033c2e8addeemr2546263wrm.4.1708040286043;
        Thu, 15 Feb 2024 15:38:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708040286; cv=none;
        d=google.com; s=arc-20160816;
        b=P/mqbRES0AfjyNEGf2jru0OX5Fy9K0RhvC09WDVKcoUlM5q72CGCweCIGy+gEdsoVY
         KS/1ewerBkhO857rypQbrzCiZ4ig34nb2Kfl81dBcXezJyCQ0IcNSS1h+q6sllwSjC5p
         lrIz2wgJd/0iebgaYSpEVz0bk+/VYvSa1TJylREfqY7LsoVovd8ScDvR6NI+uBHzTlGE
         AWM+ry1WI1J56dKGlexSPwIFVXRH+g6ZIbUilEAL/PiUB/3pBIdwyHaPNaJamS3eYY+W
         mQLSENc9AFWzXz2vK95WP/odLOK+YVMGTPVTxpFKRFi/8rOlVb95CRiakwTf1tXCXGdw
         P28A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NZ1UpqZjcTjdMt5iJXgrg3IRkY7u54tAu2yazi8L+wk=;
        fh=3BACNa81fz4G0bcGUMs2KYgHGUVo3TKzYiJEG6aAyUs=;
        b=SUOTQNi2hh9Z4aFdD6Sg40KjbUoI0bZHprxC3oDpQlbeBX8JLQi1eB/2Cov+ND7KZR
         mvVJZ6FWoypLJDrYOL8eGbhfwpLqrjgltqKaZJ+BOhz72+liEYQmuEjX9Bvx/CD3cpME
         Oxl+42Ou77hLMJaChiDRUueWubjc6R38qQzAxlw0aBAKfmF4yCKXIc6E0JuKOnK8UQO9
         iYMJitvTAibkFH98LwlBTtwyFlZs7xhw2CsFWWja7bnb1D7qcvuqEUSj2siiL6qLkq+E
         7f78t+JXN2lDdNSgr5TuOdqpMZWS5NqMJnpM2ywVovuA7UxEINruZraWTRGKW8BvAhoH
         8beA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cylmfuzQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id n1-20020a5d51c1000000b0033cddf15870si16971wrv.6.2024.02.15.15.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 15:38:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-33d118a181fso468446f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 15:38:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVi7A8QaddkCYpep1OK7XEnAv5to4TlrE6Oxtogl6TluI6r4uM4tDUpyu7AgwdRs6T7rnD+BzACzERTyuragSXoSjQxwXyNq154UQ==
X-Received: by 2002:adf:f591:0:b0:33b:51a0:4dd3 with SMTP id
 f17-20020adff591000000b0033b51a04dd3mr2432157wro.17.1708040285619; Thu, 15
 Feb 2024 15:38:05 -0800 (PST)
MIME-Version: 1.0
References: <AM6PR03MB5848C52B871DA67455F0B2F2994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
In-Reply-To: <AM6PR03MB5848C52B871DA67455F0B2F2994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 16 Feb 2024 00:37:54 +0100
Message-ID: <CA+fCnZeo3dksyFgM5w=gz7Z_djG-ddesDQ4dfhqAwosNy5+1Hw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Add documentation for CONFIG_KASAN_EXTRA_INFO
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cylmfuzQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Feb 15, 2024 at 8:17=E2=80=AFPM Juntong Deng <juntong.deng@outlook.=
com> wrote:
>
> This patch adds CONFIG_KASAN_EXTRA_INFO introduction information to
> KASAN documentation.
>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
> V1 -> V2: Fix run-on sentence.
>
>  Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
>  1 file changed, 21 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index a5a6dbe9029f..d7de44f5339d 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -277,6 +277,27 @@ traces point to places in code that interacted with =
the object but that are not
>  directly present in the bad access stack trace. Currently, this includes
>  call_rcu() and workqueue queuing.
>
> +CONFIG_KASAN_EXTRA_INFO
> +~~~~~~~~~~~~~~~~~~~~~~~
> +
> +Enabling CONFIG_KASAN_EXTRA_INFO allows KASAN to record and report more
> +information. The extra information currently supported is the CPU number=
 and
> +timestamp at allocation and free. More information can help find the cau=
se of
> +the bug and correlate the error with other system events, at the cost of=
 using
> +extra memory to record more information (more cost details in the help t=
ext of
> +CONFIG_KASAN_EXTRA_INFO).
> +
> +Here is the report with CONFIG_KASAN_EXTRA_INFO enabled (only the
> +different parts are shown)::
> +
> +    =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +    ...
> +    Allocated by task 134 on cpu 5 at 229.133855s:
> +    ...
> +    Freed by task 136 on cpu 3 at 230.199335s:
> +    ...
> +    =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +
>  Implementation details
>  ----------------------
>
> --
> 2.39.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeo3dksyFgM5w%3Dgz7Z_djG-ddesDQ4dfhqAwosNy5%2B1Hw%40mail.=
gmail.com.
