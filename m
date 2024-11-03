Return-Path: <kasan-dev+bncBCFZZKXC5EMBBCHIUS4QMGQEMEUUFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id F0DD09BBF0A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 21:52:26 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-20c8b0b0736sf53003335ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 12:52:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730753545; cv=pass;
        d=google.com; s=arc-20240605;
        b=lVsSU5ysM3LS7SlmCtrxDpMXmmnwieBIrukG8j3qOI3EhFHiLi85thKIhyCIINJQ9N
         eMXzR/GSiaft6gnC0yn37xjKE//pUmdjH/+05ki4cM0gxZtc8+DccloJKX0FJYj9OPTh
         /FFSno1BYapgXYj+4XQ58tO5cSYhO/U9VTC0iSmJC2jWq+jgC6KSRDLn+/f03RjnOelB
         QZMneHeGZh0uuU2ErJEY5WeHBvWoJS6ZDji38mOZ7azU18Hw6314NEf2MyQ6bylREW/c
         ZvjvPwbjjoC5PFFQAqOyLaPym9fPYzoPnP0HTOlNxCXLKLOIUXnJ/jxdAqgLLbE+6ddX
         fXwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=iDnYKOPmw5IkU82hliSn4TBSdTokcGqy4r5Jm/vdjF8=;
        fh=3DUQm4G9JbWauZufslv3xfNNPzJsFMgS8WjJvrTRxhU=;
        b=G4cPVn+7FLlBhmXBqrtESc3JUS7BC5jLuu0vwbHoN2Qog0rvHBIXjZg+nO5t+Aljge
         6nDTYhZANAy0N8ZACphGhwt3VHFZGnNJ/SaHrSqB8LpOYKatIabQPgGFFdDc4jaC8Lza
         WXeLdvbipU+45zPwH0Ag0fEr9B1HiMd9h85Z0hNZrhD+WJEJiLEH6U2AQosHiqoN1A0X
         2MMyK8xxQIe3SxmQsD3zu2LwIqQHW5dyZumOw3ek5uNt3OnBdgLkiBvvRml+OU30kT22
         9lXLBIM4yVmA0lOxZxhJTnRgoTsgkQDa7Xx8B9PfEBkfLhhuHZV/xE45vLGzOFDf57Hm
         FBlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QI17SSAn;
       spf=pass (google.com: domain of michaelchristopher248@gmail.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=michaelchristopher248@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730753545; x=1731358345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iDnYKOPmw5IkU82hliSn4TBSdTokcGqy4r5Jm/vdjF8=;
        b=ej/00luSF5JHF/DS4YxSfbEqm0Wc4TPKq0Q/dZcGsW7D2SqU3ud2kWxZX0KW+jFIDY
         7qRDiJ/bgS8kfnba9xteoNhGQl5kBZ4Il8HQJjAa+Fg4F/P1ZyfmsFkVcFsIf6uQpjkl
         xihboZwDKjrzh8RGJ2mpcTnmbIfNWgxa2W/WpwYY/yPqBVIvRLzprFD+69gvwfNACLf5
         mTH3tLitHRpEmx4lmAEPOEdzu9kWAoNP463UMTccUefi4ied15VLlEHOtrzF4ISFrEIT
         hrjNgdoMGnE+8V8+6guHCMllLhLopG8+4Jgh/xskKLEZnXyL9TvQ5/OI39Xst6HH7caB
         tz4w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730753545; x=1731358345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=iDnYKOPmw5IkU82hliSn4TBSdTokcGqy4r5Jm/vdjF8=;
        b=XbAqEdOzz4/FAf93CqNqND48ONsrO60Gt2kBrjCwXE2zaX00iLmoJ7LQfEog+kDyMz
         umQPPndW+EqyqKaWL/kKs/KnKcnOhrgsOTH3kFF/9y6qeFOn+SsRKBDjMEwBJi2LNdsa
         QMoTzgWZBJspiWtWhRG6/oP5l+b4zP5BaRNe3J6aSNHlJy4L4bqi5KfTYERZno6zU8pV
         m1w0G27ZCekfMAksvm1wWnuvLNEzHPuf90SY0+hjGSksi8HJqmqprCJVlS7F5vcpjitn
         7oP110iL7Y8D4RHVbtCpI13H32eZ5/hYAjG9xOBITnfjmqddvRcNgu2xwG7AVzfJuQ2O
         IaMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730753545; x=1731358345;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iDnYKOPmw5IkU82hliSn4TBSdTokcGqy4r5Jm/vdjF8=;
        b=NLlzhFqiJY7Bqn703pvxc7mC4uaJaFSib/xBW5+iADGM5EdrwVcAC9IvbQp6LZ2b7d
         qiq1NmOXlbqrRzOfibmAzlM3A/bVjElqVEFG65IXRcPlTaN8rZrv8znnCu/06bAT91UI
         Gbq3zLbfPudVYZcx4NSjsNolriugNQmNFs2ysl/qOY24qhaxj+oWnphUJRbNp94+V3dm
         mXxUiMoRP1Cg1rDN/sHE9sqH+MU3AQoj4OqBKIl2WlYy5vWGTuGkkqi09/E4dVtDOw2x
         vkAE6dSaVKqn6QCCuwZQ/Z3iLpxGlFxOnolT6S4R1Et/y6tcnoSFTBbjbarOr7cCYgoI
         jDFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFqndYaw20Hmhq8bN1VEib2rfAl3LtJ3ZZ55mEgRoL+Wm8dqRFFZGyS9eIIzZ0FksRG0C9GQ==@lfdr.de
X-Gm-Message-State: AOJu0YwKhIUq7OSz96OE6g/m/XDeAIbQmRH+LYBEUXTcrgq2gsFcTkPA
	Xr+RCPJ6gHeeJkcLvLLwdFuguIATwTXAVxb9iwEiAjZydLWTCPWV
X-Google-Smtp-Source: AGHT+IEzIvsvPQh/4M/wj2J8qq8BLWyy1iTR9fb8jiHNWCUTDEH1EhmKG7XYBNKLLllKTxbcToSrIw==
X-Received: by 2002:a17:902:d50c:b0:20b:5046:35b with SMTP id d9443c01a7336-2111b02286emr187563755ad.57.1730753544897;
        Mon, 04 Nov 2024 12:52:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c08:b0:2e2:c421:c3e with SMTP id
 98e67ed59e1d1-2e93b13bae7ls680035a91.2.-pod-prod-05-us; Mon, 04 Nov 2024
 12:52:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1NBFtX/bfPqslEbi7LLyJRBNP/HnJqP27sdTZCQMQyawNu4t8djLgRg5aupwpQJFEVMhgLVa6yM8=@googlegroups.com
X-Received: by 2002:a17:90b:5306:b0:2e2:c15f:1ffe with SMTP id 98e67ed59e1d1-2e94bdf49acmr19063996a91.0.1730753543296;
        Mon, 04 Nov 2024 12:52:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730753543; cv=none;
        d=google.com; s=arc-20240605;
        b=MJhFs9jkZ3qq1oPMwLQjE1D/QAZ5F2PMjYp/mtRfGvHH3hn3CVZj4M9eo1UTdROf7N
         y/v+hWuiW9C8ooXb4I4FST1q5qHZFIcTFesqM7u+z2WiYcDUanZe0scj+PbPTWLNQoJi
         KYQJ18xUFUm+B5z/z6BVPYOeoj/9aVPgwYw5KE4jrgQqXcGRSXSpidHvGvUx0TLlIRGS
         y9JexSLEwWh10EOkdmvtJwUeck/y1ENfjA1kqRRtAVHsF+VXEcnMoG+zVOw4HptvJzXS
         /htc2+Wr8U/ye+IediYKY1oFb2Nnepw7EdGX62Fg93xOcuLJ/7tEIQCei3NrgeOdoTFj
         e8pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=8Wn4GVwFadoUTX9g/xl19RIqGFl3ehLTBzgDWsi70O8=;
        fh=LFGlsOa5Z36X+GnWfZ7QDbNGuHCSv5Rxw/TFi1feXsM=;
        b=UgXkPxuQ/5Mgd1BDSbW2FhfK+WzcbKUL1jE5tdTFbm7eLknvKLtbCfdQ8NxzYZTnHB
         Dtal4z36FEnAfBW7jw9893RAXSaIVQx/CkRsPR8VRPk0QwQW7zM0N+nprUJ+JG2gpiVK
         v8SmjD5DAc61B2QcWwycWynERz/dEyLFSMEsA0W0LOVk26VJ2vviQ8UhVQcMUdvdH63M
         GgfVQ00d/lPj+4algQAyp8DMzARR2u8YzWPMLEMPdjK09Cz8Ti69dG829wwFEA9Fuobw
         YfB9zSnWrl+q8MtMu1DNfUoBWy0EaLHiBWF+G1YhA7YGdak/Vah6W/EcV0kUHiLfidfr
         9aWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QI17SSAn;
       spf=pass (google.com: domain of michaelchristopher248@gmail.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=michaelchristopher248@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x2b.google.com (mail-oa1-x2b.google.com. [2001:4860:4864:20::2b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e92fc11aa8si466177a91.3.2024.11.04.12.52.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 12:52:23 -0800 (PST)
Received-SPF: pass (google.com: domain of michaelchristopher248@gmail.com designates 2001:4860:4864:20::2b as permitted sender) client-ip=2001:4860:4864:20::2b;
Received: by mail-oa1-x2b.google.com with SMTP id 586e51a60fabf-288642376bcso2283746fac.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 12:52:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtEsRiKtzIQJkzVCIBtXXWR0OcBjQ7sfant7BpCjeeIjiecegfAPv8nyge6OsoNZ9jVs9bx1sHrtQ=@googlegroups.com
X-Received: by 2002:a05:6870:2107:b0:25e:bd07:4743 with SMTP id
 586e51a60fabf-2949e994c00mr11509985fac.0.1730753542413; Mon, 04 Nov 2024
 12:52:22 -0800 (PST)
MIME-Version: 1.0
From: Felipe Andres <michaelchristopher248@gmail.com>
Date: Mon, 4 Nov 2024 08:50:51 +1000
Message-ID: <CAH_=wz+0pr32o_x8n5wCwBDJ-RU7cM42yft5tLRZYbAjm5RsGQ@mail.gmail.com>
Subject: Hallo
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000016e82506261c7683"
X-Original-Sender: michaelchristopher248@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QI17SSAn;       spf=pass
 (google.com: domain of michaelchristopher248@gmail.com designates
 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=michaelchristopher248@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--00000000000016e82506261c7683
Content-Type: text/plain; charset="UTF-8"

Hallo, haben Sie meine E-Mailerhalten?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAH_%3Dwz%2B0pr32o_x8n5wCwBDJ-RU7cM42yft5tLRZYbAjm5RsGQ%40mail.gmail.com.

--00000000000016e82506261c7683
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><span style=3D"color:rgb(85,85,85);white-space:nowrap">Hal=
lo, haben Sie meine E-Mailerhalten?</span><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CAH_%3Dwz%2B0pr32o_x8n5wCwBDJ-RU7cM42yft5tLRZYbAjm5RsGQ%40mail.gm=
ail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/CAH_%3Dwz%2B0pr32o_x8n5wCwBDJ-RU7cM42yft5tLRZYbAjm5RsGQ%40=
mail.gmail.com</a>.<br />

--00000000000016e82506261c7683--
