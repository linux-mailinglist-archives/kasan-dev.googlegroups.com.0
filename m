Return-Path: <kasan-dev+bncBCDOJNHYXAJRBKX22PCAMGQE6ZCSYTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8535DB1DD76
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 21:23:23 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-619a86410dcsf1845922eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 12:23:23 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754594602; x=1755199402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jycZiqgUxWKfq4+yeiCJI0/JeL3J+YfhEdlO4ifsJzk=;
        b=hdYxmyI+TYS4oaVvNTnIB0eDKobcaPDQHhCOn7oLoe2IzkyC9CfsYath59XmX47TcT
         1b4cYHgWmTFSLu0kyowHWnv8clkhi3Xx70X4JdnNdNpanh/0n/nZ6JT82VVPPl2K5ls4
         ow2k6P3MyLuPQ24kh84Mv+6J7l0inplhiD82Xwn/PHiUAZ413c2E1osteDv9dzWAeXRt
         CWARqj0O68kmck0e/Fz3IeUD7jg/DWveOzGOXgBEtnUzvb/0YANXQmw8dlFzRLqENIVP
         WodlxTLEOOHvBpe/0b3qwfNhkgbY2rbys2gV6rKv2A1/K4/idzDFha2MQpOWcbXh5vjm
         w1Fg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754594602; x=1755199402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jycZiqgUxWKfq4+yeiCJI0/JeL3J+YfhEdlO4ifsJzk=;
        b=isM0CjXsfCjxydWfJYoYTDyLD0Mf61vlhe6XgG3YCQd2g9XDlsX2JeTpcv822Dxr0N
         ztPsjNA4VxLq7xFCQvbHkmIDsnyf3bnta04xD4dbsURHnzEIX4yfRD0MvJfhx4NsMSpT
         tftn9Uy/FOn7gVtWVtNd+s+VN6V9lEK3jmILDs1onn/DGZWBSYUonh+PyEaMrJYDUgJy
         /FTDD9qcxwpJBJ78NJGxe/T+WUrzfNEgk/KtQRceC26ej1ZdyZ+l4BNVMZauRBOCMH7L
         vdqQ98/TzRoe457mUnH2uQir+nX11Op9WrUuptbE+cMYO8Tp2ZsnKszpXq6P82MZ4P3i
         /sQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754594602; x=1755199402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jycZiqgUxWKfq4+yeiCJI0/JeL3J+YfhEdlO4ifsJzk=;
        b=u4zZzo5deOiVeTa8qp3ETkFHfiHnUZ5N3xxrwyEmTF0M62p4qVupyn8Q/gAxlwylo5
         v4lcN62omEpWUPwJ4/7GMh+wS1zEoPHqGOPGpO5zlNmBPkxMFEVJTmoRsSi46OzvPzbJ
         TivoX3iYhbZoGNTV3n36VfGJqJbdv6Gb/M4tkrUQQqyG/ieYcUsQlnYuWnpQaFflj9jT
         ZCNTDRnOaj+glXqtzcAw69XVyk35C3K9knF/Oeg4EYwHTpVKCTqpCDmqnF+yVoUauhoa
         wnOm4ZiN1QjWSuodp5xt0MxcmEvaN3lT4qRzlMYiZgYEdqp5At0/OfwolWhzJIzL9EGC
         yKbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVY5ZsVGOu+GfBRcIYsHXPUUdsHB/QMrzpTuWcWSLqlNANVvBHJXdD9P1xebig5KS/qp/db+Q==@lfdr.de
X-Gm-Message-State: AOJu0YxFznjRjKIURcE/icSppYiJfu3qcB8KB6mkt6EcptIDXAaiXI9E
	nvsy+V8YHYZkD6Jy/7EmF2lWulm2ZDEKSdcbM/a0u9tqwF/0fHjX+gvF
X-Google-Smtp-Source: AGHT+IE1+Rnj7i5mbSRHVdOQy8AFtqboPy8Bu4VMBEwTa5Cz34I82g90f//SPpUY72Id4yz6MR5EVw==
X-Received: by 2002:a05:6870:1708:b0:308:fc2b:b78 with SMTP id 586e51a60fabf-30c21158ad2mr288664fac.41.1754594602188;
        Thu, 07 Aug 2025 12:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcYjOXjS+5TnF5R0w24C8P5vS+vbNT6v3rE0qVItRPYNQ==
Received: by 2002:a05:6871:76ee:b0:30b:cb7c:ba90 with SMTP id
 586e51a60fabf-30bfe92b480ls484726fac.2.-pod-prod-02-us; Thu, 07 Aug 2025
 12:23:21 -0700 (PDT)
X-Received: by 2002:a05:6808:2287:b0:435:7256:3f8c with SMTP id 5614622812f47-43598064e08mr261184b6e.38.1754594601169;
        Thu, 07 Aug 2025 12:23:21 -0700 (PDT)
Date: Thu, 7 Aug 2025 12:23:20 -0700 (PDT)
From: Klkl _klkl <qwzxfgui@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <80ecec8c-7e1e-46a5-9ed4-0fe9243b5bcbn@googlegroups.com>
Subject: s
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_2192_1270018996.1754594600453"
X-Original-Sender: qwzxfgui@gmail.com
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

------=_Part_2192_1270018996.1754594600453
Content-Type: multipart/alternative; 
	boundary="----=_Part_2193_325869608.1754594600453"

------=_Part_2193_325869608.1754594600453
Content-Type: text/plain; charset="UTF-8"

f

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/80ecec8c-7e1e-46a5-9ed4-0fe9243b5bcbn%40googlegroups.com.

------=_Part_2193_325869608.1754594600453
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

f

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/80ecec8c-7e1e-46a5-9ed4-0fe9243b5bcbn%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/80ecec8c-7e1e-46a5-9ed4-0fe9243b5bcbn%40googlegroups.com</a>.<br />

------=_Part_2193_325869608.1754594600453--

------=_Part_2192_1270018996.1754594600453--
