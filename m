Return-Path: <kasan-dev+bncBDU4B6HP7QHRBUX3WWSAMGQERIQWGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BBABB733FE1
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jun 2023 11:33:07 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4f767665374sf1209189e87.3
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Jun 2023 02:33:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686994387; cv=pass;
        d=google.com; s=arc-20160816;
        b=vHRt0xT2IA7WrY7SbEigsIRTxjTlISKJdiatYjEKAYz7wTBoQliQbJO4pDBkcibgXC
         Xv/rhcgAD1v6fH75PlhPcrv3s8I1ihL2MBuX2CpeROzDCdRCmyBAboJ13xdMhwOiTI+4
         vk9KHHcBqQUZW1hIudrT9BQYxM5ABjpa3Upo0oVjo0udc/VM5g7nWBGnWfQd3OXtS1Nz
         47YzUccQ6tv1lDGt6NGf/eBwM/MOl7Us0L4Ir+1Q13KQkjAJFj5/OnwljV7TD7yU/HBW
         LCRut72jstOgj0NWVdZKsQH4FN9i3tpQXppWCDOuvXOF4xqfIXFGpQ1aL5lCoybfWh4K
         kEmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=rf3M3paGJonaz/XDOBbFWn/nfD8uzIcSifbBhV8otaw=;
        b=rgox7f4qa07QsHJEKgbxUU2mYrPqoXgLiOc7uxukOrO29cqRlKpJaUgIip9oSCwCNX
         1DJ3UbmkvEWRKFDQtY4qkB3lS3zOPyI9jBR8+OoNyoXz5CZXWHPukT9uWMs6+RQvurNo
         V8gnPFzOgDHKwOi182EqeZvl7YhBaJ0xpr6pjih9EvSuy3IAlyuiKR+hhi55gB0vChZh
         IM6+ZI3pyHBQ+SYf29xg6UmCN+NiPZL0sIny8TlQNQzHt4rdNUJlTPnvStOUt7gJujMi
         ll6TrBKBaZ2wacGsLpKEqu+Gl2mIGWpu82x2S2z0jYZBLu6nMaDTirx52fQxOSRq18L4
         /i0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="kpxst9/A";
       spf=pass (google.com: domain of frunkbunches@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=frunkbunches@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686994387; x=1689586387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rf3M3paGJonaz/XDOBbFWn/nfD8uzIcSifbBhV8otaw=;
        b=ozQHMAL1iI1ksWkZBVLW0Rb3bhlXgA50hSqH9LjT4Fo2cgyAU4hbYq7E6S8MlM7Bzt
         JbfQA5WaIt6oHvuvuWS/yjBv90gdqUczH+SBV5MIKW7i2Afx1JDSHmZoHUpcEq5Gmmi7
         LVov5fBvBCpJ0il02YgFYlQIEB7mQmTXFnrND2PIOXumCf9cInT94bVUTFp2QH2iiIIq
         J+PtnvPH5h7rVWQsheaCg/LD0n6/KFyb6eX7tDCfxUpvhMmEzVH/bvDqdPoYh5snZmLt
         fCaoirxI1STo3Rnz2KSmW4AOHgbLHQCyZHPp6Vdlc6Y8WsqvPep1QAzkez88pHMCDBtF
         n0Zw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1686994387; x=1689586387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=rf3M3paGJonaz/XDOBbFWn/nfD8uzIcSifbBhV8otaw=;
        b=UFVVur9hhboo70aSJqKkdFtyAS5OC58+IW50FzF8FDG2Z5i45RF3Ct6M2otldI3NL0
         P1EVwLDoudEW3iZKu0nKD/Ph8/lCsYbojoPFxY982puCqcSKeEJvOd9bivMFXCa6D0sv
         x7pKOJFoQpN6pKsJxEDXQidh2GfnOGxrhzcIbv3Ww6gP9FEAgmOPgpSqOr6BXUjUo/aA
         4Iw7gTmFPSfi6nVs2/mC9hbCW68fhNI+fp5YFPAOCco+isKNfg0spi9wDwwt4xjp5C6S
         btuI4y0X/+xBfi5Dew/4Vp3LdGBVaQd5joe5ftSJJMVLjmR7CFyobKg1RF0Ihv9oGsfT
         NQQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686994387; x=1689586387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rf3M3paGJonaz/XDOBbFWn/nfD8uzIcSifbBhV8otaw=;
        b=I8spSKzct+RlaEXyN2Bpkapg3wribSA03MGGIOKAexiRtGqL7rvYcwgsd8ElGEvm9F
         WVJ1f0WDREKlQW9tjU6U/9SRDQRZvZ96TGVYXgMYkbizIDh/kMonPwYLMgLBBf7dQcT9
         g3tXfQD69aDDCaLb4ZKvxug3IweF6XQzcwEsjPeg2C7FJLThtp1xz5Mg4wMMKinww3wu
         pb487XP++/vtIqtkySxCre/aNp/ZMd3eiZISx77I9LKyjPyH5dBqDKFAG+FSxYMd66kv
         LCIH7I/4tYATgnZx6jFZBwqLJB7MgxM5m3YRLBx1DnrZFF+0T+zQ8zgRhvhAAkZViKCW
         vaSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyqteEnQrf2Mac1dNuliDN+0eOQW4HV4CiSCpG7H9tKf2uSQIIC
	7BZU2drEbcrJnyA4hcPlneg=
X-Google-Smtp-Source: ACHHUZ6KyR+kEfS7GhxhqZKGUz9aKEvGXxACskmeSx7ycKXcefOfyKF6HqQmygCTpYHUl8W1Kh92wg==
X-Received: by 2002:a19:6d12:0:b0:4f7:604f:f4c8 with SMTP id i18-20020a196d12000000b004f7604ff4c8mr2908235lfc.18.1686994386291;
        Sat, 17 Jun 2023 02:33:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6513:0:b0:4f2:71a1:53f1 with SMTP id z19-20020a196513000000b004f271a153f1ls458048lfb.0.-pod-prod-01-eu;
 Sat, 17 Jun 2023 02:33:04 -0700 (PDT)
X-Received: by 2002:a19:505d:0:b0:4f8:5ede:d447 with SMTP id z29-20020a19505d000000b004f85eded447mr709371lfj.28.1686994384870;
        Sat, 17 Jun 2023 02:33:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686994384; cv=none;
        d=google.com; s=arc-20160816;
        b=r3fYK5wVXy0MG5LsnsH9A9Ecl/hXsMVtVVxP9PWztTkW4ZLKjD00l8I4DetlqkIWIJ
         6L3rY7JaEt3AmSRtQGwKjNxomu34/0XQli+8YXPL1duDNSUHDAGl9j7HlezHSzIMkzef
         KFMBKqVYrlgS8prqCU0afl0hGvIeHOMznNA831lVADokRjfBqt2pc/2sxtSBUug5uNsz
         WbdDRKpSUbnJByWx+kr0TckIsMSkGmMtUChTLgFaGqW/RA8/sOT5C+eriRRiGy4g+L+W
         DSu6pM06LLZgYrFJDFf3BjsxcV58cimjeh0aYo8jp+92JVPd+ne1Okrb35JOQUJWdoYd
         acHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=nXhiEFMc4N8ZiSiVb5NoO11Ih96RlnIYtKssPGTYDUA=;
        b=kRT65nFVYLayZY8b+ms946Yd1EVlwpUYridK5M35f8sLEjPr1bolMj9umw7LM4biPz
         xMeAzufPGn1V12HcVHYpVWawh/XIj/Su2pyN22uzd/D2s/sb+KpSLiNrgl7CuocThVIt
         2+Xd+bXMNSF+JT0YWsZtAsp9eui5lsvaLfbjNk3n5qLnF2SP/qdvP/LvA0jZvJ8tDFry
         /G+6wGHKC6bor4mQzIIZstlXmbkX1f64nZzFxiYVifOtt7uXU5dgQV0lJ0Cqof8UtiAg
         y6F3ho9703QHi+edUuKj4bF8wnRyZ8SgPtC5RSKUIHU4FVHJT7IaUWe2EXCFgpUXQRRC
         oGFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="kpxst9/A";
       spf=pass (google.com: domain of frunkbunches@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=frunkbunches@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id m17-20020a0565120a9100b004f4e6ea3713si1372962lfu.8.2023.06.17.02.33.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Jun 2023 02:33:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of frunkbunches@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-4f4b2bc1565so2124270e87.2
        for <kasan-dev@googlegroups.com>; Sat, 17 Jun 2023 02:33:04 -0700 (PDT)
X-Received: by 2002:a19:671e:0:b0:4f6:278b:713e with SMTP id
 b30-20020a19671e000000b004f6278b713emr2559667lfc.42.1686994384250; Sat, 17
 Jun 2023 02:33:04 -0700 (PDT)
MIME-Version: 1.0
From: Frunk Bunches <frunkbunches@gmail.com>
Date: Sat, 17 Jun 2023 19:32:22 +1000
Message-ID: <CAFNG+6gDEwoGh=2_gvShsq6Js5DHaXhU-h=3gtfm3A4fafoMPA@mail.gmail.com>
Subject: This debug
To: david@fromorbit.com, kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="00000000000002ecac05fe4ffd20"
X-Original-Sender: frunkbunches@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="kpxst9/A";       spf=pass
 (google.com: domain of frunkbunches@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=frunkbunches@gmail.com;       dmarc=pass
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

--00000000000002ecac05fe4ffd20
Content-Type: text/plain; charset="UTF-8"



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFNG%2B6gDEwoGh%3D2_gvShsq6Js5DHaXhU-h%3D3gtfm3A4fafoMPA%40mail.gmail.com.

--00000000000002ecac05fe4ffd20
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAFNG%2B6gDEwoGh%3D2_gvShsq6Js5DHaXhU-h%3D3gtfm3A4fafo=
MPA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAFNG%2B6gDEwoGh%3D2_gvShsq6Js5DHaXhU-h%3D3gt=
fm3A4fafoMPA%40mail.gmail.com</a>.<br />

--00000000000002ecac05fe4ffd20--
