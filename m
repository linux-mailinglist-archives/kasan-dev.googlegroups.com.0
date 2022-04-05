Return-Path: <kasan-dev+bncBDCOZ2MMZAOBB5W7WGJAMGQE3NVEGUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id BBB0D4F3CA3
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 18:36:07 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id i19-20020a5d9353000000b006495ab76af6sf8785398ioo.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 09:36:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649176566; cv=pass;
        d=google.com; s=arc-20160816;
        b=L4Vnz1D9uiq54sdkbP2nCRXU1nPtgxMYBRemSXUoykIznQzmJDnLyWY+pGZnDg6dmi
         ikVmbJT4RmYvD0gToRUr8clDqkPCUdDXl9tn22TFfu832JJ9m45SvO4MslWdfTtkUtSk
         EDg0t+ijazcFnUi3+eXHQvHMtIucrc28y+6vdvxymuJcJxFd3mdat/XxsMt5e2foF01E
         WDBCBIYFtuaFRKyZlPxsswDYHX8lR/iS8t9ln+GzttXUMFp15roSyRcvg0Rmqml1NEQe
         fh3yr0r2sthqZqXeVizvPLEiNGstaDhQ3GshQE4CPza3ffYU9JkiwpidxqKczry19xoc
         r9vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=VCGlxkZu2MfxKr6/V62vXTp+ylrJfJtly3YbOqZq9HY=;
        b=xF1wQlprJWNmZq57NMBaKBn5o1gGkxwiBTk+gcAbD8B4APsmqW9JUg3Zw29nV32vyU
         fkLUc27Yet/5OsE//AjErBm+AwAkNbYBtXgNwVhiPDGuKtwmuHoxo62ATnzr0n3iq4VT
         u8f7dNez1Fr17x6MeZNSZM74395B+FI1V8gp/oaNEZhhJCBkIzzG2gIuvbHSgJ2GGifl
         evr9fdj2gbkp3Vv9xU9s9+XK78XIHdXNVrVRE4rqFjo9NL04s7EdApctHlaK4CGX8uZb
         hD3+40xOV9249AxP3kyerq18zdQ7tqDDVFJLKfCTxlkIdBR3e/wUdO4+dew9B5DXfnpa
         du+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Jxq6SVt8;
       spf=pass (google.com: domain of monicabrownn17@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=monicabrownn17@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VCGlxkZu2MfxKr6/V62vXTp+ylrJfJtly3YbOqZq9HY=;
        b=lnVSUWQEoFdYX7LrAWHeaCmygn8KtI+2M5Rkjemh72ec+DLpqv94vhB80sg2lT5W05
         t37UaAgIRqha1Jv5LmjVoZVqDL/SUXDVLkxDOB7jvjSKGtxthGqarfaO5cPDL/k3MAjg
         QEIIntJvTDVokBxtJcuHqtSpxfPt5C5qc83SCv3BSGsZQc7mQhCEWl8URVWc0U2BXzLy
         KcO7sUMz7OsgTbSPhYj2nI5xKYbQqiUashRPwC4Q/cUL1PTotWHtxHIJ+5492nWlEEMy
         BN7R1GbUmKSFTaTP5Frubwc9v4le54Q4/tZkZ3whBU53/RE3eE367jKO0QcTcO0tNVtJ
         I+7Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VCGlxkZu2MfxKr6/V62vXTp+ylrJfJtly3YbOqZq9HY=;
        b=TskoPrALcZTV9+y7TgsBS2OmPen35drAbOZBRJf40unXodU0zESXK2JInwNDa+4mBY
         OS1RXSwUjt7Ds/MsjM27zFSmFmE0tJv7gyhKVNXuAJ2DryPx8Pq+jLdkMswLOk+402U+
         gs3JfGWK+yHNQIrz+Aisc9yz3u1dCMDLsGR9qRk33EJ8TRRPaYSiJCop+vzAsbfUYuwl
         rtmxZBOWRtAt8QklK9dakGohGsJMzoc9a3OehHhXQi8spzRv5CkgA7yc3MeQJ/FRw0FH
         SuKcmsb4sJte+Y0qjOvpv0AbhiMMUe43fofTxHGwOUtHuc5d0CqXfPPkeH+V/YdnB7fI
         DgVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VCGlxkZu2MfxKr6/V62vXTp+ylrJfJtly3YbOqZq9HY=;
        b=HglNxd5BmmtkmphKXaU+/uFfg1JXkek0RUvJf/8YOFqxRI8crYTO8qg3ddQj5uIFGk
         xmiFkO+mSQRfFUaeM6DMGWKUsaxPbGlk5ya08eMeEHEAjqFKEPlMEXoo8rrPv/Tbdt6u
         DNGhVTwCEK0GGcZw2E3BTXL2YWMWE1Uj60LtcB4Lo52nbWM23sGIQCHhEHYctH2eTJS+
         Qb8dxzfNky7MxI6NqoQC97KlqIzIyKqCfdWwXgaqvnUwC9f7ZU0u0YtP23E2+7aBN5Wz
         fO8zcHMRsXlSTJ+LEkz/E+TbfWbP9wgwWgMMjSMiopUfDRHajIkKYLLpmRjyghhBebid
         wcPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BHcQgP90TPL+iQyHTR7hHVEk5uRLZ4M2dIadUcaoZnugInR1S
	KMmJqbPiCipsraRZhjcRZRQ=
X-Google-Smtp-Source: ABdhPJzmvnFMV0q4UKcDngen9w0rxKq384zsrcZw2Iw1yxBUnyntAAsO+xacqdXaayO/hGhZSUn4Cw==
X-Received: by 2002:a6b:fb15:0:b0:64c:9b3a:2182 with SMTP id h21-20020a6bfb15000000b0064c9b3a2182mr2210651iog.211.1649176566559;
        Tue, 05 Apr 2022 09:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:37a5:b0:31a:7e1b:b322 with SMTP id
 w37-20020a05663837a500b0031a7e1bb322ls3600990jal.9.gmail; Tue, 05 Apr 2022
 09:36:06 -0700 (PDT)
X-Received: by 2002:a05:6638:d0c:b0:323:e62b:2490 with SMTP id q12-20020a0566380d0c00b00323e62b2490mr2645599jaj.86.1649176566212;
        Tue, 05 Apr 2022 09:36:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649176566; cv=none;
        d=google.com; s=arc-20160816;
        b=km7UaR6pOV/eNBjATUeCIqS3HTKEvkaIivycxr0TkElm8QqdmGlk1QWa/BDa8jS8Ov
         LYcC1uCZtu9KHZymxH+b8TlCblXDlh1HKOhtPxuP3i1ucf+DC8mqNFL7t0XKgF5PyRcm
         Ed+bvEVsMFG6mIFedy+mXe8GhqXfOz0XDfhaRFKaJ4GFmndK79eY1hZ5U2J0ubBTqIkZ
         U6RxBXbnkWBvoPJZ//xOI18w1cEVGcZrU44V849FLDv0y8Y5jF0MekTGagOPxR99/Aub
         u5FzD98coPrrGRDjbDnl9NJQq9pAyMzzj1726YyTBq40OLG56K4U2mO1iTbBj7uVL7Mq
         Ddgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=eXgoE6NIjJFDsKg6iekD4ys0M5Zt9aDt1lp+49k/LJs=;
        b=BublueX/oWTLlSgGWXn8m7Bfjzw4qDxNgxSqQzAKFLzXH2Fnn6elyULJwUzOK6fG7n
         x/ibw1iCXpLOcjlHytqjOSrz5DTkwBD4oikggQb28foRx8RpC0AVlzLifRJndZD4bkxh
         P65dz59uiyWXk9+fl+4MLWrqJOFkfPbhj69METhjeFUthOD4vgb1irK224OvYVHfChJ/
         OdrF1ihkS5vOfVseMCqPOsvIm5KQ7pIdXjqRmAI0h9KyFUn4lVToYUfJHa9MQF6GkZyy
         aip/D6oZEm0s+KD5ICknx7Cw+rBMcpWVoqbS/HvoZ2SNFnwtcVDykkHBG5vUDjAQziu7
         rEIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Jxq6SVt8;
       spf=pass (google.com: domain of monicabrownn17@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=monicabrownn17@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id t17-20020a5e9911000000b00641b4797049si893936ioj.2.2022.04.05.09.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 09:36:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of monicabrownn17@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id o10so5443588ple.7
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 09:36:06 -0700 (PDT)
X-Received: by 2002:a17:90b:4a02:b0:1c6:c1a1:d65c with SMTP id
 kk2-20020a17090b4a0200b001c6c1a1d65cmr5047212pjb.97.1649176565720; Tue, 05
 Apr 2022 09:36:05 -0700 (PDT)
MIME-Version: 1.0
From: monica brown <monicabrownn17@gmail.com>
Date: Tue, 5 Apr 2022 16:35:53 +0000
Message-ID: <CADrkLNUz9GTAJLVPqiS_8RB0y-nss2-rituA=EjkBjHtEiVALQ@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000005f29ee05dbead749"
X-Original-Sender: monicabrownn17@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Jxq6SVt8;       spf=pass
 (google.com: domain of monicabrownn17@gmail.com designates
 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=monicabrownn17@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000005f29ee05dbead749
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Ich bin Monica, ich habe etwas Wichtiges mit Ihnen zu teilen. Antworten Sie
mir f=C3=BCr weitere Einzelheiten

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADrkLNUz9GTAJLVPqiS_8RB0y-nss2-rituA%3DEjkBjHtEiVALQ%40mail.gmai=
l.com.

--0000000000005f29ee05dbead749
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Ich bin Monica, ich habe etwas Wichtiges mit Ihnen zu teil=
en. Antworten Sie mir f=C3=BCr weitere Einzelheiten<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CADrkLNUz9GTAJLVPqiS_8RB0y-nss2-rituA%3DEjkBjHtEiVALQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CADrkLNUz9GTAJLVPqiS_8RB0y-nss2-rituA%3DEjkBjHtEi=
VALQ%40mail.gmail.com</a>.<br />

--0000000000005f29ee05dbead749--
