Return-Path: <kasan-dev+bncBCI4ZGNIZAIRBDNLYKSAMGQEWH7AZRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F157735D29
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 19:51:11 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-25e948f434csf3015762a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jun 2023 10:51:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687197070; cv=pass;
        d=google.com; s=arc-20160816;
        b=jOpJ6ijVFHpVVUyfJiobcP2GZ9Qdkby43999YbWe8OxRBmgqUAPLQm/xy7oJFDXPEF
         OUDqKruoYNYUJYtH324SOnwDR/uydPhXJaiHElZhTQl2WT342XVH17MohpYOC8CNLndv
         vsj5BlxXZNNRuo6Ge3zj+cHCOus2PYL0T9S3OkX8gXTI8Cau79Zumq2DvOS01dnWzNUn
         aLgTaWyvgBNkNnxAOBVfmvoXJPjFAnlwlD6rHVlrL7bPg9Z79IV3IhFcAhUZHyk+4XrS
         HhKAeS8tE/t0adfO/5fZA6Ib6AYYrCGnoqOLCSuEw3/W4ea+aC8tNJ6wtJuAbWEoXfID
         iB9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=XTwoTb2YF0Vg+SWujXZIdUQ0CNYN46uEv5xEU5tWojE=;
        b=OI3zUCHCOPHXr6W2SsyrcGny+sGsf0ZXIc05pGyQqniob10qonmT0eeIC7WX9YYjEW
         X1gkNVJXvyoIBZdvoqBo09vSqSTVrTr1vNlhAv5flA7bqQT1TnaZ23n/dEyqJqz69UN0
         +VRjwc7+LB9C82my2N8a5+laKetCL4YVugk0DhMeoG7HJLgAzk+Hb/mtU122/wfavF0n
         mCTLDFKy8lN58b/pdr8Qs5lrvd+sv4AaPDGhv3pJyrMtuhoBWUMJtJAn3eKucoD2rAo5
         Q282h30wEyaUijStqXObWrecp04+aNeoMb99T7NkQZBqIAoUMpBGZWwXyD/ZLTwJlKAO
         287Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Ni2dvTtE;
       spf=pass (google.com: domain of salvinokyz@gmail.com designates 2001:4860:4864:20::31 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687197070; x=1689789070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XTwoTb2YF0Vg+SWujXZIdUQ0CNYN46uEv5xEU5tWojE=;
        b=feBg9xEyYSBUDVu7qreTVjf3pbZcoeI0j4YJr8dawu5K59IgULyHQ9937a5t+krtOo
         eaUEU/Ws8Z290DYt1SHK4WUSkbC7YFKJ4SgLqWkFsvYfv/zbF63BNHhJw2I+Z3JGn5qP
         LzJhe5YJaFkj0qO2MIpHWY2RrSBgX6teKZamcfHZjWu3PBxPM71WbYyBgQd8zX9j9ZTA
         gswMRcfdr/fd1mwECbcxGzkqXBgEYB/ouFISTRK5JUuS2Zj02K8F4/J3vFXC/OEBokc7
         Uf8OGufOqPFQOfmmBcTo75lICNpt6qkCr4Whz18jCoNJD3MYZT2equ1V4CCNVrKm5kvj
         jUDg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687197070; x=1689789070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=XTwoTb2YF0Vg+SWujXZIdUQ0CNYN46uEv5xEU5tWojE=;
        b=jhOHXAEco6u+kqjj+XLqEn0vhd4kZA1KOdRGxybZyzkFNSQUmTkSSEp6WmUFc83tKG
         spH87TCQPs72Gevh4vBSdvPq0kPKx4R/CVrrk9XRCs29IwnUCUJLJYJ4LQU7jw34pyMX
         lM8SDXZaoJ2r+jSPaANTVCr1Z0aV2VInLyaikDnLB93J/W6FC11twFmrZcmvCcmEGZ7x
         ru2c6yOa2iDdOCSM0gICGj/lpANG3em1Y8RWzS0BT8lZZgBmXd3HbTb2tCavk5pbZijn
         GF9FfhFo9KExo+l71ecDQCm6R9IKySXEFWfaTOdjipzX0BYhOJSKeV0J+6OnxK/SaoPQ
         TiIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687197070; x=1689789070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XTwoTb2YF0Vg+SWujXZIdUQ0CNYN46uEv5xEU5tWojE=;
        b=h72o3rknNCTt12iGS7nrFsJJJ8TcDkRkttTbSwmOTr7C1DfuRFAbt5ysYcE+CqjvcH
         /qmM4cfYBYiPb14CwAQEcM4qmvtdwrDPIGkgMEGBp9ELtnzQn+tcZSpxTDBM/EPfnned
         oVy2PbbtjvB5TcIDBl8X3FfoJ9G75SUPh9mBYVR7WZsDWvU0KKKQuOQ32eDJB+0LioY1
         b5Lgeo669eQWdPAZ6woOiLbysSQn4VSKNAlblxOquu4wxhA3T/n/3d1m8V45oj8fks3L
         odQXwyTFTMl+I90e6USmUe4tF6Dr8DlCA/OUbGVUpb0Hy4knIH9ces1ub9LycxywnExH
         ouvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzmGVTIsSntYBoFMzUzXleNGX5i15Poor2F3S9G20rRsLH9Ehn/
	/bA/gsoGxJwZIUm/8KOUvVM=
X-Google-Smtp-Source: ACHHUZ5JhFtD8pizbebx6aV89higaczCFCd1avvebpbdhkR4KXhkeZJRv1PvvPZPhvREY4kf49eazw==
X-Received: by 2002:a17:90a:c292:b0:24e:3452:5115 with SMTP id f18-20020a17090ac29200b0024e34525115mr9813480pjt.37.1687197069287;
        Mon, 19 Jun 2023 10:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f98f:b0:259:ba1f:55f8 with SMTP id
 cq15-20020a17090af98f00b00259ba1f55f8ls3019304pjb.0.-pod-prod-03-us; Mon, 19
 Jun 2023 10:51:08 -0700 (PDT)
X-Received: by 2002:a17:903:25c9:b0:1b5:694:b1a9 with SMTP id jc9-20020a17090325c900b001b50694b1a9mr9146901plb.32.1687197068588;
        Mon, 19 Jun 2023 10:51:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687197068; cv=none;
        d=google.com; s=arc-20160816;
        b=tBGK8W4bGZvWJ8mI1Ci3w5/uOYPvlabMdhFYgxYZ5BhIUJrROKqJMbP84YAtPirmCB
         6r3An+INELc4nJirJYRBW5Xaqq3aobHb3fvybTLJGVcCAjVoGiSghbGT+S/5MdkJfFuA
         iwiWGsQ8jp7AMDL8xBAI68tEItHRFxyRLZovzjw4eC3ATJLt3WP0K1ix053zoBaVDEyj
         74CLBJn+2S0kAVVtj4WoFOkTCpVJBgY5mWXzo++V3J76TJAb3eNtqegg2kmh3sa7k6wG
         vQDjK+yw+lNj6WkHaPpElGspLzhFGxyNj2vK7YuiRmyrzs78cSiA+cbrODE5i2NU9adO
         Ba/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=Jz6dgO41JUnxRfr6h/GQYJsyNzq5Zn4dhBjwcMj/4FM=;
        b=cv+1gbrq9BawZ+g0/h00XepOspR1W8w97teSMqkpzYseJwpYnE0XH6mNlYplZPuuOn
         RSplXHwOz+tyjD4zsSTBvuvbRJqgtpQrp07ISq7LLKv6XWxeIWLRwm9q02M2bwTZcmNl
         ArK6rL9EvlTzvKD81Elsm2jKXSQawpGro0BC8zZCB/ixrTkIYsEkS8zzljbTOt9G0B79
         xpsGXpmxaj3JhcOcE5c3kHOYRlrSXBdBF5fCrJdZ5S4zbAK5z03D51hqqal2cg17iM/x
         bFS1KrWxNsU9LWq3WEv3KIWaXQf4RH2l7IKwQMPdRrcLxu32zXNB1oDY2HTzBl1mUnyQ
         TW5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Ni2dvTtE;
       spf=pass (google.com: domain of salvinokyz@gmail.com designates 2001:4860:4864:20::31 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x31.google.com (mail-oa1-x31.google.com. [2001:4860:4864:20::31])
        by gmr-mx.google.com with ESMTPS id bj11-20020a170902850b00b001a4fe95baf3si14020plb.3.2023.06.19.10.51.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jun 2023 10:51:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of salvinokyz@gmail.com designates 2001:4860:4864:20::31 as permitted sender) client-ip=2001:4860:4864:20::31;
Received: by mail-oa1-x31.google.com with SMTP id 586e51a60fabf-1a9a2724a62so3408099fac.2
        for <kasan-dev@googlegroups.com>; Mon, 19 Jun 2023 10:51:08 -0700 (PDT)
X-Received: by 2002:a05:6870:44c1:b0:196:5f5f:7c7b with SMTP id
 t1-20020a05687044c100b001965f5f7c7bmr4780424oai.20.1687197067839; Mon, 19 Jun
 2023 10:51:07 -0700 (PDT)
MIME-Version: 1.0
From: Kyz Salvino <salvinokyz@gmail.com>
Date: Tue, 20 Jun 2023 04:50:26 +1100
Message-ID: <CAJoHdx+8fBj_hOWZsgTQEVFjOA4-J1ajK9z-7=W6WqXKG6G=gA@mail.gmail.com>
Subject: 
To: linux-riscv@lists.infradead.org, Kasan <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000e50d8b05fe7f2dc3"
X-Original-Sender: salvinokyz@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=Ni2dvTtE;       spf=pass
 (google.com: domain of salvinokyz@gmail.com designates 2001:4860:4864:20::31
 as permitted sender) smtp.mailfrom=salvinokyz@gmail.com;       dmarc=pass
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

--000000000000e50d8b05fe7f2dc3
Content-Type: text/plain; charset="UTF-8"

The World hold U high quality ok with the kids and treatment of a few
minutes in all good here being the first one to sell the whole kit hit &
caboodle

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJoHdx%2B8fBj_hOWZsgTQEVFjOA4-J1ajK9z-7%3DW6WqXKG6G%3DgA%40mail.gmail.com.

--000000000000e50d8b05fe7f2dc3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto">The World hold U high quality ok with the kids and treatm=
ent of a few minutes in all good here being the first one to sell the whole=
 kit hit &amp; caboodle=C2=A0</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJoHdx%2B8fBj_hOWZsgTQEVFjOA4-J1ajK9z-7%3DW6WqXKG6G%3=
DgA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAJoHdx%2B8fBj_hOWZsgTQEVFjOA4-J1ajK9z-7%3DW6=
WqXKG6G%3DgA%40mail.gmail.com</a>.<br />

--000000000000e50d8b05fe7f2dc3--
