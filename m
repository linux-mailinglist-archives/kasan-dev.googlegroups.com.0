Return-Path: <kasan-dev+bncBDM2ZIVFZQPBBDMHTHEAMGQEIC6JF3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EAE1CC283DA
	for <lists+kasan-dev@lfdr.de>; Sat, 01 Nov 2025 18:29:50 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-429cd1d0d98sf22591f8f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Nov 2025 10:29:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1762018190; cv=pass;
        d=google.com; s=arc-20240605;
        b=kuhR9DbVkkWfvjYHwSL7XBUBuITBSRtabVx9BCqdvQuiKNyP66EPNS0o1a3ZHt2rDj
         IAEY8MxYrGxq5dM8nGTr7yfbPEwbQFL/cZmimE8O3NxHyRNmUfp6G+aRQz1UuJB15TiP
         w8nVREa/IONbIof+yP86wbOfCDlZFA1vZpCdcE8CCwo451ndXUhO9LvZ5cIDM1vwPHt0
         8tPOjXRUwI4p+kq5vnET6kfBbMkTBnPSMWtuDgF4Mv2uuvBMAAsf5SmhAWh7rVIsK3TE
         9ECtMXPTJzW1E1b1re2n9xQtcjSSyPpc5JTxvr6d6F6Lnh/ARw6y2YU/BlOvyemfmd4z
         5D+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=4Ays/c7YXxkSclMwQZCKCOOmFFYuO+IuGT9nVxJsfxY=;
        fh=gWxFJJ3NgZmPTCV65dFfPVyZnIQrpa1rwn+nSBGYNVc=;
        b=IJt0ItZUb2OvECq2z3MXi8SGP/jtXgAXT5uIF2GL6TBEVSaL0ZEcufXfkkZ6jQr4mC
         U5Xx2H6I9TwOjCOJ3yH94L+Ex58ECDkHt9k8a3ERnDmb51Pu1ZAKsP7CulHdkRTU2449
         DJLCjk6VsxHcHKpmrP85ZCMP/i5aZs+AYGIgm9QCD2dxJ4kCP3ReXmo40OCXC/VfbXpf
         fdV6uExKNXONlHR7oAtJwWu6myOEa9kbehhtofyTWDuEvk/fYoHbbtSalBwabjJMwcjg
         WuaqCkfxCxy+i8WkJvE+uTp4wsKMG9SEROKiOjdif3/HsL3YrqeiO9gOGU+3VjX+Cnoc
         Wx1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="MubfUZ/C";
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762018190; x=1762622990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4Ays/c7YXxkSclMwQZCKCOOmFFYuO+IuGT9nVxJsfxY=;
        b=wIvmq3Ah6HqJYGewrZubPbVvPCdOZLmCbaCk9SXPj/NH/es+xP1s96AQr4f7p0ctw4
         ZZ4ycG4nZ7e8YyYzgW/JrAK9OEykP8Uwvamc1sBJX8Vl7hd0Q789ZtAEymkfItSObnQ4
         ymr5sDy2qLMRn0NWPAvAE4i2Ut7kU2flk3IbFO1LEWItTAepbOy+mO1mgCG9IoP4OEV0
         1PxWI4NYPVvoaXcDb/p2yvw3Es++rJwN442XRCmOnpmy6OLSgj2YQJREpp247DQfWefR
         fxYh7fJbwPsZl7hj4z3+ZU6i/4eF8aa1C6GCyzyt45ME7egBGH8O4SYLzJgk5yBK2gxO
         dx/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762018190; x=1762622990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4Ays/c7YXxkSclMwQZCKCOOmFFYuO+IuGT9nVxJsfxY=;
        b=O6q9rNrxCXEtapbK2vyNh8wFnpNvbFVh6RlnxxBee1o/GWvysACw94cEZUf9Fi5MGf
         q6mkudkJIHa2SYjQwPyqiHsYqQgAAR4I9JJbKxYi2vCvKwPKK8Kaij7LAaZehv+hfUhf
         h0kbrvqEczhpaclFoX+70Y1gtHE0FSnkPipev/xrYf3GVWxcafwI3QOX13HkRYhyLYbi
         BzYdTmg18Wh3Q7SAe9jyuumLrvRUR+DSNKJGo1EYQ6M/sPf+8WlXQQJdFIf0AUGVQZG9
         Zoe4lNlT2VVAxmxNP9Z6UdzdUnFuXSUtzHSLAFg9RWz/zoiD2THn4OdZvJVfx9kEGDaB
         +HZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762018190; x=1762622990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4Ays/c7YXxkSclMwQZCKCOOmFFYuO+IuGT9nVxJsfxY=;
        b=e2wEEQJQSMUIiEdRMVkCGg7PPMb10bL55fgAtvN2L609/q3/p2KNGuC8edus2FpSu0
         TPHFE4d+A1xBDl1yWivIXvYVbaRNRo4ScfOSrweS/RQWeZs3laqStvxm2dCQdWXIhYn4
         UQAjrp5pAnd/G5uexjU4Al2+naVer1g+KxaHr0+Lmi4Zb2W2wliXXeRruc17d+2IYwp/
         99HawDbs+FSGMuAuDOcrWl3HAQw/nYV+7uJ3HmZOFfbGM7b1lUGZDFEeBTryZDqvMmBB
         Qxlss3bR1D8bDbvkOn+EWJ2EpdzrBWdZ9fZdpCCcak4hYJyyCscD2iigddP7HFSU6gpP
         7/rA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvb+3DkIU3BypUcmoyzbsjSYQILIAfY4a2WDL1E2+4pPd+W1VBkIEFvfEocDAq/jfIbPCBKA==@lfdr.de
X-Gm-Message-State: AOJu0YzxC8nQCAsaNeyhF7HzUGG9rZy31yE8Pby8uQmDemzW8qu5rgKB
	+1aNWjaVzqWMzPEcsOpNsV7hSk5HHp5UY7Fx/Lox0b9tQU5P6t0nCcik
X-Google-Smtp-Source: AGHT+IGb9g3KrRSGqqecQ/es7K5IAt6bqBG7eQmH00huRGEXjAT44L5fxcRadP9Rn+IkaG4muJnmpw==
X-Received: by 2002:a05:6000:41d8:b0:429:be56:e508 with SMTP id ffacd0b85a97d-429be56e6e4mr5798688f8f.58.1762018189942;
        Sat, 01 Nov 2025 10:29:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aiH1N3x24umB5VMq9xmcuC08VHxbSvm2xWIhE+/mZbVA=="
Received: by 2002:a05:6000:24c2:b0:424:21d6:1fad with SMTP id
 ffacd0b85a97d-429b4e06fe8ls2608135f8f.1.-pod-prod-07-eu; Sat, 01 Nov 2025
 10:29:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUp7Wl5DJQRYwTgDtHdD7902EMCnC5gNJ8CBe4XfTIA9jKiong9nwISObY5EYcwC5ceE+lMlWyNQ1g=@googlegroups.com
X-Received: by 2002:a5d:5c89:0:b0:429:b9bc:e81c with SMTP id ffacd0b85a97d-429bd6bf186mr6306602f8f.48.1762018187258;
        Sat, 01 Nov 2025 10:29:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1762018187; cv=none;
        d=google.com; s=arc-20240605;
        b=MPEvcSIzGCgE6DhnwQaxZstSAA5REdi2KRvNILdD34aUi0+xwxjcGHtzxHwFObThry
         +CeonEyax+MOeRV/MHmyTBo44iEkPAcebtxkd7Uhanlmac/59bx5F6wejCoHqEJzGxJX
         E0qNPBstxd+aPDGyCOMTVmN9A1Rw0PvZkoRjPrIh/CAfnBwBJDBlQJdBmLeKu7CxHRYm
         M4Bqc5t7neiKVxNp1cO2i1DI2C6Xt5WgEkW931HPJhyRn1KSn90FRJ074E5WuqJrdcet
         dz7FEDfsISng5ysuFkGFi5AGWMCRc3OV/eT5d8eA6gPHBuERhrEWb0Svc0Ua1OS1sKFU
         L1hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=L9I0Yqki4Mr84c4sAoWGD6Y9mxjVpo+eKzsnBGB3tWM=;
        fh=E+VsGG4YnooPL0o3VU22qfofoVRm2uzst+foxrYomO4=;
        b=fD3CcCNkvMACN4usjFqTutHn0FZ1ffOUzlNi7sBGBeq7rHKPj46QjST5u3Dtp0+Ppv
         YpcJirPITS5uiSTjaF5wpbaCDLdSCHljvWmKqhO3Of90zOsTE3Tk+StzqI+bmkGp9mRr
         L8XcK4JKUcwO6RlJq+jW8dlAicqxNLAo5kQgm4vMCYkoct1yc4bdngJLKQ45mAC/4vCs
         w42GldKkS5wGiP1JFt0f6m/qYZSGiM+MY5suypX0/z2VGTX12gru0yHSwgsMN+9a7PSa
         4g9yLthNCczqTrEKXUckkK/5ZOflATP/ZED3zc9X6U8CEwKdBaahrOyFKinXy4TpAXuE
         34aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="MubfUZ/C";
       spf=pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429c1390846si178793f8f.7.2025.11.01.10.29.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Nov 2025 10:29:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id a640c23a62f3a-b70406feed3so672835766b.3
        for <kasan-dev@googlegroups.com>; Sat, 01 Nov 2025 10:29:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzaae5tbRBiJBIWunzOyxGaYXsZXPW3oSv41wvqhDJBX5FhN1P21hCjHe05MBC3Xky6Xi1jjoBy3A=@googlegroups.com
X-Gm-Gg: ASbGnctq3ly2p5VFtRnCkQmzKrMxaD1ey/85feV7vn9n6rs5O8FSvB/YxmQrE9PdVDL
	SsoGRzlYA8D8wuRbEOMX1+WpWogL+yMEZsFQJwzlMHu/b7nVMoGGLL5K2/j/bMdl/wC19vfV01I
	ncCAQ6Zt7e41kEjUxPgkThWmzwRcZxCEF0m8kcorGVoefOSSLRZe4MjLEi9LMXJ8YIzo6/JNzAm
	mcSbdzjNFofbvdxrgwSnXc5GJkt43JbBsXhF+It5OC6MZXAi6lNGg+PkZz1QC/VrhD0
X-Received: by 2002:a17:906:270b:b0:b4e:d6e3:1670 with SMTP id
 a640c23a62f3a-b70700db162mr523684666b.11.1762018186360; Sat, 01 Nov 2025
 10:29:46 -0700 (PDT)
MIME-Version: 1.0
From: smr adel <marwaipm1@gmail.com>
Date: Sat, 1 Nov 2025 19:29:32 +0200
X-Gm-Features: AWmQ_bl16XVSwKaRaC472O8IK2QyANKLzIRtSWZsUhVRakD2OVjN-nmJzlHW0c8
Message-ID: <CADj1ZKnkeNnGg8A31muTUJRsWd07d=MSXazgmOf3FVvEMLADgg@mail.gmail.com>
Subject: =?UTF-8?B?2KXYr9in2LHYqSDYp9mE2YXZhti42YXYp9iqINin2YTYrtmK2LHZitipINio2KfZhNiw?=
	=?UTF-8?B?2YPYp9ihINin2YTYp9i12LfZhtin2LnZitmI2KfZhNiq2K3ZhNmK2YTYp9iqINin2YTZhdiq2YLYr9mF?=
	=?UTF-8?B?2KnCoNin2YTYsNmD2KfYodin2YTYp9i12LfZhtin2LnZiiDZgdmKINil2K/Yp9ix2Kkg2KfZhNmF2YY=?=
	=?UTF-8?B?2LjZhdin2Kog2YjYp9mE2KzZhdi52YrYp9iqINin2YTYrtmK2LHZitipKNmC2YrYp9iv2Kkg4oCTINiw?=
	=?UTF-8?B?2YPYp9ihINin2LXYt9mG2KfYudmKIOKAkyDYqti32YjZitixINmF2KTYs9iz2Yog4oCTINij2KvYsdmF?=
	=?UTF-8?B?2KzYqtmF2LnZiik6QXJ0aWZpY2lhbCBJbnRlbGxpZ2VuY2UgaW4gTWFuYWdpbmdOb25wcm9maXQmIENo?=
	=?UTF-8?B?YXJpdHkgT3JnYW5pemF0aW9ucyDYp9mE2YHYqtix2Kk6INmF2YYgOSDYpdmE2YkgMTMg2YbZiNmB2YU=?=
	=?UTF-8?B?2KjYsSAyMDI1INin2YTZhdmD2KfZhjog2KfZhNmC2KfZh9ix2Kkg4oCTINis2YXZh9mI2LHZitipINmF?=
	=?UTF-8?B?2LXYsSDYp9mE2LnYsdio2YrYqSDYo9mIINi52YYg2KjZj9i52K8g2LnYqNixINmF2YbYtdipIFpPT00o?=
	=?UTF-8?B?2YHZiiDYrdin2YQg2KrYudiw2LEg2KfZhNit2LbZiNixKSDYp9mE2KzZh9ipINin2YTZhdmG2LjZhdip?=
	=?UTF-8?B?OiDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin2YTYpdiv2KfYsdmK2Kkg?=
	=?UTF-8?B?2KfZhNmF2YLYr9mF2Kk62YrYtNmH2K8g2KfZhNmC2LfYp9i5INi62YrYsSDYp9mE2LHYqNit2Yog2Ko=?=
	=?UTF-8?B?2K3ZiNmE2YvYpyDYsdmC2YXZitmL2KfZhdiq2LPYp9ix2LnZi9in2Iwg2KzYudmEINmF2YYg2KfZhNiw?=
	=?UTF-8?B?2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDYo9iv2KfYqdmLINin2LPYqtix2KfYqtmK2KzZitipINmE?=
	=?UTF-8?B?2KrYudiy2YrYsiDYp9mE2YPZgdin2KHYqSDZiNin2YTYtNmB2KfZgdmK2KnZiNiq2K3ZgtmK2YIg2Kc=?=
	=?UTF-8?B?2YTYo9ir2LEg2KfZhNmF2KzYqtmF2LnZiiDYp9mE2YXYs9iq2K/Yp9mFLiDZitmH2K/ZgSDZh9iw2Kcg?=
	=?UTF-8?B?2KfZhNio2LHZhtin2YXYrCDYpdmE2Ykg2KrZhdmD2YrZhiDZgtmK2KfYr9in2Ko=?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000015feed06428bd467"
X-Original-Sender: marwaipm1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="MubfUZ/C";       spf=pass
 (google.com: domain of marwaipm1@gmail.com designates 2a00:1450:4864:20::635
 as permitted sender) smtp.mailfrom=marwaipm1@gmail.com;       dmarc=pass
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

--00000000000015feed06428bd467
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

ICAgICrYpdiv2KfYsdipINin2YTZhdmG2LjZhdin2Kog2KfZhNiu2YrYsdmK2Kkg2KjYp9mE2LDZ
g9in2KEg2KfZhNin2LXYt9mG2KfYudmKINmI2KfZhNiq2K3ZhNmK2YTYp9iqINin2YTZhdiq2YLY
r9mF2KkqDQoNCg0KDQoq2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZiiDZgdmKINil2K/Y
p9ix2Kkg2KfZhNmF2YbYuNmF2KfYqiDZiNin2YTYrNmF2LnZitin2Kog2KfZhNiu2YrYsdmK2Kkq
DQoNCijZgtmK2KfYr9ipIOKAkyDYsNmD2KfYoSDYp9i12LfZhtin2LnZiiDigJMg2KrYt9mI2YrY
sSDZhdik2LPYs9mKIOKAkyDYo9ir2LEg2YXYrNiq2YXYudmKKToNCg0KKkFydGlmaWNpYWwgSW50
ZWxsaWdlbmNlIGluIE1hbmFnaW5nIE5vbnByb2ZpdCoqICYgKipDaGFyaXR5IE9yZ2FuaXphdGlv
bnMqDQoNCltpbWFnZTog8J+Xk++4j10q2KfZhNmB2KrYsdipOiog2YXZhiA5INil2YTZiSAxMyDZ
htmI2YHZhdio2LEgMjAyNQ0KW2ltYWdlOiDwn5ONXSrYp9mE2YXZg9in2YY6KiDYp9mE2YLYp9mH
2LHYqSDigJMg2KzZhdmH2YjYsdmK2Kkg2YXYtdixINin2YTYudix2KjZitipDQpbaW1hZ2U6IPCf
krtdKtij2Ygg2LnZhiDYqNmP2LnYryDYudio2LEg2YXZhti12KkgKipaT09NKiogKNmB2Yog2K3Y
p9mEINiq2LnYsNixINin2YTYrdi22YjYsSkqDQpbaW1hZ2U6IPCfjpNdKtin2YTYrNmH2Kkg2KfZ
hNmF2YbYuNmF2Kk6KiDYp9mE2K/Yp9ixINin2YTYudix2KjZitipINmE2YTYqtmG2YXZitipINin
2YTYpdiv2KfYsdmK2KkNCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQoqW2ltYWdl
OiDwn46vXSoq2KfZhNmF2YLYr9mF2Kk6Kg0KDQrZiti02YfYryDYp9mE2YLYt9in2Lkg2LrZitix
INin2YTYsdio2K3ZiiDYqtit2YjZhNmL2Kcg2LHZgtmF2YrZi9inINmF2KrYs9in2LHYudmL2KfY
jCDYrNi52YQg2YXZhiDYp9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfYudmKDQrYo9iv2KfYqdmL
INin2LPYqtix2KfYqtmK2KzZitipINmE2KrYudiy2YrYsiDYp9mE2YPZgdin2KHYqSDZiNin2YTY
tNmB2KfZgdmK2Kkg2YjYqtit2YLZitmCINin2YTYo9ir2LEg2KfZhNmF2KzYqtmF2LnZiiDYp9mE
2YXYs9iq2K/Yp9mFLg0K2YrZh9iv2YEg2YfYsNinINin2YTYqNix2YbYp9mF2Kwg2KXZhNmJINiq
2YXZg9mK2YYg2YLZitin2K/Yp9iqINmI2YXZhtiz2YjYqNmKINin2YTZhdmG2LjZhdin2Kog2KfZ
hNiu2YrYsdmK2Kkg2YXZhiDYqtmI2LjZitmBINiq2YLZhtmK2KfYqg0K2KfZhNiw2YPYp9ihINin
2YTYp9i12LfZhtin2LnZiiDZgdmKINin2YTYpdiv2KfYsdip2Iwg2KfZhNiq2YXZiNmK2YTYjCDY
p9mE2KrYrti32YrYt9iMINmI2KfZhNiq2YjYp9i12YQg2KfZhNmF2KzYqtmF2LnZiiDZhNiq2K3Z
gtmK2YINCtmG2KrYp9im2Kwg2KPZg9ir2LEg2YHYp9i52YTZitipINmI2KfYs9iq2K/Yp9mF2Kku
DQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KKltpbWFnZTog8J+Or10qKtin2YTY
o9mH2K/Yp9mBINin2YTYqtiv2LHZitio2YrYqToqDQoNCtio2YbZh9in2YrYqSDYp9mE2KjYsdmG
2KfZhdisINiz2YrZg9mI2YYg2KfZhNmF2LTYp9ix2YMg2YLYp9iv2LHZi9inINi52YTZiToNCg0K
MS4gICDZgdmH2YUg2KrYt9io2YrZgtin2Kog2KfZhNiw2YPYp9ihINin2YTYp9i12LfZhtin2LnZ
iiDZgdmKINin2YTYudmF2YQg2KfZhNiu2YrYsdmKINmI2KfZhNmC2LfYp9i5INi62YrYsSDYp9mE
2LHYqNit2YouDQoNCjIuICAg2KrYtdmF2YrZhSDYp9iz2KrYsdin2KrZitis2YrYp9iqINix2YLZ
hdmK2Kkg2YTYqtit2LPZitmGINin2YTYo9iv2KfYoSDZiNin2YTYrdmI2YPZhdipINmB2Yog2KfZ
hNis2YXYudmK2KfYqi4NCg0KMy4gICDYp9iz2KrYrtiv2KfZhSDYo9iv2YjYp9iqINin2YTYsNmD
2KfYoSDYp9mE2KfYtdi32YbYp9i52Yog2YHZiiDYpdiv2KfYsdipINin2YTYqtio2LHYudin2Kog
2YjYp9mE2YXYtNin2LHZiti5Lg0KDQo0LiAgINiq2K3ZhNmK2YQg2KfZhNio2YrYp9mG2KfYqiDZ
hNiv2LnZhSDYp9iq2K7Yp9iwINin2YTZgtix2KfYsSDZiNiq2K3ZgtmK2YIg2KfZhNij2KvYsSDY
p9mE2KfYrNiq2YXYp9i52YouDQoNCjUuICAg2KrYudiy2YrYsiDYp9mE2LTZgdin2YHZitipINmI
2KfZhNmF2LPYp9ih2YTYqSDYp9mE2LHZgtmF2YrYqSDZgdmKINil2K/Yp9ix2Kkg2KfZhNmF2YjY
p9ix2K8uDQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0NCg0KKltpbWFnZTog8J+RpV0q
Ktin2YTZgdim2Kkg2KfZhNmF2LPYqtmH2K/ZgdipOioNCg0KICAgLSDYp9mE2YLZitin2K/Yp9iq
INin2YTYqtmG2YHZitiw2YrYqSDZgdmKINin2YTYrNmF2LnZitin2Kog2YjYp9mE2YXZhti42YXY
p9iqINin2YTYrtmK2LHZitipLg0KICAgLSDZhdiz2KTZiNmE2Ygg2KfZhNiq2K7Yt9mK2Lcg2YjY
p9mE2KXYr9in2LHYqSDYp9mE2YXYp9mE2YrYqSDZgdmKINin2YTZgti32KfYuSDYutmK2LEg2KfZ
hNix2KjYrdmKLg0KICAgLSDZhdiz2KTZiNmE2Ygg2KfZhNiq2K3ZiNmEINin2YTYsdmC2YXZiiDZ
iNin2YTYqtmC2YbZitipINmB2Yog2KfZhNmF2KTYs9iz2KfYqiDYp9mE2K7Zitix2YrYqS4NCiAg
IC0g2KfZhNmF2LPYqti02KfYsdmI2YYg2YjYp9mE2LnYp9mF2YTZiNmGINmB2Yog2YXYrNin2YTY
p9iqINin2YTYqtmG2YXZitipINin2YTZhdis2KrZhdi52YrYqSDZiNin2YTZhdiz2KTZiNmE2YrY
qSDYp9mE2KfYrNiq2YXYp9i52YrYqS4NCg0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
DQoNCipbaW1hZ2U6IPCfp61dKirYp9mE2YXYrdin2YjYsSDYp9mE2KrYr9ix2YrYqNmK2KkgKDUg
2KPZitin2YUpOioNCg0KKtin2YTZitmI2YUg2KfZhNij2YjZhDoqINmF2K/YrtmEINil2YTZiSDY
p9mE2LDZg9in2KEg2KfZhNin2LXYt9mG2KfYudmKINmI2KrYt9io2YrZgtin2KrZhyDZgdmKINin
2YTYudmF2YQg2KfZhNiu2YrYsdmKLg0KKtin2YTZitmI2YUg2KfZhNir2KfZhtmKOiog2KfZhNil
2K/Yp9ix2Kkg2KfZhNiw2YPZitipINmE2YTZhdi02KfYsdmK2Lkg2LrZitixINin2YTYsdio2K3Z
itipINio2KfYs9iq2K7Yr9in2YUg2KPYr9mI2KfYqiDYp9mE2LDZg9in2KENCtin2YTYp9i12LfZ
htin2LnZii4NCirYp9mE2YrZiNmFINin2YTYq9in2YTYqzoqINiq2K3ZhNmK2YQg2KfZhNio2YrY
p9mG2KfYqiDZiNin2YTYqtmG2KjYpCDYqNin2K3YqtmK2KfYrNin2Kog2KfZhNmF2KzYqtmF2Lkg
2YjYqNix2KfZhdisINin2YTYr9i52YUuDQoq2KfZhNmK2YjZhSDYp9mE2LHYp9io2Lk6KiDZhti4
2YUg2KfZhNi02YHYp9mB2YrYqSDZiNin2YTYrdmI2YPZhdipINin2YTYsdmC2YXZitipINmB2Yog
2KXYr9in2LHYqSDYp9mE2KzZhdi52YrYp9iqLg0KKtin2YTZitmI2YUg2KfZhNiu2KfZhdizOiog
2KXYudiv2KfYryDYrti32Kkg2KfYs9iq2LHYp9iq2YrYrNmK2Kkg2LHZgtmF2YrYqSDZhNmE2YXZ
hti42YXYqSDYp9mE2K7Zitix2YrYqSDigJMg2K/Ysdin2LPYqSDYrdin2YTYqS4NCi0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQ0KDQpbaW1hZ2U6IPCfk55dKtmE2YTYqtiz2KzZitmEINmI
2KfZhNin2LPYqtmB2LPYp9ixOioNCtijLyDYs9in2LHYqSDYudio2K8g2KfZhNis2YjYp9ivIOKA
kyDZhdiv2YrYsSDYp9mE2KrYr9ix2YrYqA0KW2ltYWdlOiDwn5OyXTAwMjAxMDY5OTk0Mzk5IOKA
kyAwMDIwMTA2Mjk5MjUxMCDigJMgMDAyMDEwOTY4NDE2MjYNCg0KLS0gCllvdSByZWNlaXZlZCB0
aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJlIHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91
cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQg
c3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2
K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5jb20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZp
c2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FEajFaS25r
ZU5uR2c4QTMxbXVUVUpSc1dkMDdkJTNETVNYYXpnbU9mM0ZWdkVNTEFEZ2clNDBtYWlsLmdtYWls
LmNvbS4K
--00000000000015feed06428bd467
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"rtl"><p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=
=3D"text-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;m=
argin:0in 0in 8pt;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;=
"><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New =
Roman&quot;,&quot;serif&quot;">=C2=A0=C2=A0=C2=A0=C2=A0</span></b><b><span =
lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;">=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=
=86=D8=B8=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9 =D8=
=A8=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=
=86=D8=A7=D8=B9=D9=8A
=D9=88=D8=A7=D9=84=D8=AA=D8=AD=D9=84=D9=8A=D9=84=D8=A7=D8=AA =D8=A7=D9=84=
=D9=85=D8=AA=D9=82=D8=AF=D9=85=D8=A9</span></b><b><span dir=3D"LTR" style=
=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot=
;"></span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=C2=A0</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A5=
=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =
=D9=88=D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=
=D9=8A=D8=B1=D9=8A=D8=A9</span></b><b><span dir=3D"LTR" style=3D"font-size:=
18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"></span></b>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0in=
 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi:e=
mbed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"RTL"></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font=
-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span=
 dir=3D"RTL"></span><span dir=3D"RTL"></span>(=D9=82=D9=8A=D8=A7=D8=AF=D8=
=A9 =E2=80=93 =D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=
=D9=8A =E2=80=93 =D8=AA=D8=B7=D9=88=D9=8A=D8=B1 =D9=85=D8=A4=D8=B3=D8=B3=D9=
=8A =E2=80=93 =D8=A3=D8=AB=D8=B1
=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A):</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">Artificial Intelligence in Managing
Nonprofit</span></b><span dir=3D"RTL"></span><span dir=3D"RTL"></span><b><s=
pan lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></spa=
n>
&amp; </span></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&=
quot;Times New Roman&quot;,&quot;serif&quot;">Charity Organizations</span><=
/b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New=
 Roman&quot;,&quot;serif&quot;"></span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;ser=
if&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=97=93=EF=B8=8F"></s=
pan><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times=
 New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=AA=D8=B1=D8=A9:</=
span></b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Tim=
es New Roman&quot;,&quot;serif&quot;"> =D9=85=D9=86 9 =D8=A5=D9=84=D9=89 13=
 =D9=86=D9=88=D9=81=D9=85=D8=A8=D8=B1 2025<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=93=8D"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=83=
=D8=A7=D9=86:</span></b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-f=
amily:&quot;Times New Roman&quot;,&quot;serif&quot;"> =D8=A7=D9=84=D9=82=D8=
=A7=D9=87=D8=B1=D8=A9 =E2=80=93 =D8=AC=D9=85=D9=87=D9=88=D8=B1=D9=8A=D8=A9 =
=D9=85=D8=B5=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=A8=D9=8A=D8=A9<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=92=BB"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A3=D9=88 =D8=B9=D9=86=
 =D8=A8=D9=8F=D8=B9=D8=AF =D8=B9=D8=A8=D8=B1 =D9=85=D9=86=D8=B5=D8=A9 </spa=
n></b><b><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times =
New Roman&quot;,&quot;serif&quot;">ZOOM</span></b><span dir=3D"RTL"></span>=
<span dir=3D"RTL"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;fo=
nt-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><span dir=3D"RTL">=
</span><span dir=3D"RTL"></span>
(=D9=81=D9=8A =D8=AD=D8=A7=D9=84 =D8=AA=D8=B9=D8=B0=D8=B1 =D8=A7=D9=84=D8=
=AD=D8=B6=D9=88=D8=B1)</span></b><span lang=3D"AR-SA" style=3D"font-size:18=
pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"><br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=8E=93"></span><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-fami=
ly:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=AC=D9=87=
=D8=A9 =D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9:</span></b><span lang=3D"=
AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quo=
t;serif&quot;"> =D8=A7=D9=84=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B9=D8=B1=D8=
=A8=D9=8A=D8=A9 =D9=84=D9=84=D8=AA=D9=86=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=
=A5=D8=AF=D8=A7=D8=B1=D9=8A=D8=A9</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=8E=AF"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D9=82=D8=AF=D9=85=D8=
=A9:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D9=8A=D8=B4=D9=87=D8=AF =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =
=D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A =D8=AA=D8=AD=D9=88=
=D9=84=D9=8B=D8=A7 =D8=B1=D9=82=D9=85=D9=8A=D9=8B=D8=A7
=D9=85=D8=AA=D8=B3=D8=A7=D8=B1=D8=B9=D9=8B=D8=A7=D8=8C =D8=AC=D8=B9=D9=84 =
=D9=85=D9=86 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=
=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D8=A3=D8=AF=D8=A7=D8=A9=D9=8B =D8=A7=D8=B3=
=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D9=84=D8=AA=D8=B9=D8=B2=
=D9=8A=D8=B2 =D8=A7=D9=84=D9=83=D9=81=D8=A7=D8=A1=D8=A9 =D9=88=D8=A7=D9=84=
=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9
=D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=D8=AB=D8=B1 =D8=A7=
=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A =D8=A7=D9=84=D9=85=D8=B3=D8=AA=
=D8=AF=D8=A7=D9=85.<br>
=D9=8A=D9=87=D8=AF=D9=81 =D9=87=D8=B0=D8=A7 =D8=A7=D9=84=D8=A8=D8=B1=D9=86=
=D8=A7=D9=85=D8=AC =D8=A5=D9=84=D9=89 =D8=AA=D9=85=D9=83=D9=8A=D9=86 =D9=82=
=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA =D9=88=D9=85=D9=86=D8=B3=D9=88=D8=A8=D9=8A =
=D8=A7=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=
=D8=B1=D9=8A=D8=A9 =D9=85=D9=86 =D8=AA=D9=88=D8=B8=D9=8A=D9=81 =D8=AA=D9=82=
=D9=86=D9=8A=D8=A7=D8=AA
=D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=
=D8=A7=D8=B9=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9=
=D8=8C =D8=A7=D9=84=D8=AA=D9=85=D9=88=D9=8A=D9=84=D8=8C =D8=A7=D9=84=D8=AA=
=D8=AE=D8=B7=D9=8A=D8=B7=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=
=D9=84 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A =D9=84=D8=AA=D8=AD=
=D9=82=D9=8A=D9=82 =D9=86=D8=AA=D8=A7=D8=A6=D8=AC
=D8=A3=D9=83=D8=AB=D8=B1 =D9=81=D8=A7=D8=B9=D9=84=D9=8A=D8=A9 =D9=88=D8=A7=
=D8=B3=D8=AA=D8=AF=D8=A7=D9=85=D8=A9.</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=8E=AF"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D8=A3=D9=87=D8=AF=D8=A7=D9=
=81 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9:</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR=
-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;">=D8=A8=D9=86=D9=87=D8=A7=D9=8A=D8=A9 =D8=A7=D9=84=D8=A8=D8=B1=
=D9=86=D8=A7=D9=85=D8=AC =D8=B3=D9=8A=D9=83=D9=88=D9=86 =D8=A7=D9=84=D9=85=
=D8=B4=D8=A7=D8=B1=D9=83 =D9=82=D8=A7=D8=AF=D8=B1=D9=8B=D8=A7
=D8=B9=D9=84=D9=89:</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">1.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D9=81=
=D9=87=D9=85 =D8=AA=D8=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=
=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =
=D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=
=D9=8A =D9=88=D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=BA=D9=8A=D8=B1
=D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">2.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=B5=D9=85=D9=8A=D9=85 =D8=A7=D8=B3=D8=AA=D8=B1=D8=A7=D8=AA=D9=8A=D8=AC=
=D9=8A=D8=A7=D8=AA =D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D9=84=D8=AA=D8=AD=D8=B3=
=D9=8A=D9=86 =D8=A7=D9=84=D8=A3=D8=AF=D8=A7=D8=A1 =D9=88=D8=A7=D9=84=D8=AD=
=D9=88=D9=83=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=
=D8=A7=D8=AA.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">3.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=A7=
=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=
=D9=84=D8=B0=D9=83=D8=A7=D8=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=
=D8=B9=D9=8A =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AA=
=D8=A8=D8=B1=D8=B9=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=D8=B4=D8=A7=D8=B1=
=D9=8A=D8=B9.</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">4.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=D8=AA =
=D9=84=D8=AF=D8=B9=D9=85 =D8=A7=D8=AA=D8=AE=D8=A7=D8=B0 =D8=A7=D9=84=D9=82=
=D8=B1=D8=A7=D8=B1 =D9=88=D8=AA=D8=AD=D9=82=D9=8A=D9=82 =D8=A7=D9=84=D8=A3=
=D8=AB=D8=B1 =D8=A7=D9=84=D8=A7=D8=AC=D8=AA=D9=85=D8=A7=D8=B9=D9=8A.</span>=
</p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0.5=
in 8pt 0in;text-align:center;line-height:normal;direction:rtl;unicode-bidi:=
embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">5.<span style=3D"font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;font-size-adjust:none;font-kerning:auto=
;font-feature-settings:normal;font-stretch:normal;font-size:7pt;line-height=
:normal;font-family:&quot;Times New Roman&quot;">=C2=A0=C2=A0
</span></span><span dir=3D"RTL"></span><span lang=3D"AR-SA" style=3D"font-s=
ize:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;">=D8=AA=
=D8=B9=D8=B2=D9=8A=D8=B2 =D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =
=D9=88=D8=A7=D9=84=D9=85=D8=B3=D8=A7=D8=A1=D9=84=D8=A9 =D8=A7=D9=84=D8=B1=
=D9=82=D9=85=D9=8A=D8=A9 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=
=D9=84=D9=85=D9=88=D8=A7=D8=B1=D8=AF.</span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=91=A5"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=81=D8=A6=D8=A9 =D8=A7=D9=
=84=D9=85=D8=B3=D8=AA=D9=87=D8=AF=D9=81=D8=A9:</span></b></p>

<ul type=3D"disc" style=3D"margin-bottom:0in">
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=82=D9=8A=D8=A7=D8=AF=D8=A7=D8=AA
     =D8=A7=D9=84=D8=AA=D9=86=D9=81=D9=8A=D8=B0=D9=8A=D8=A9 =D9=81=D9=8A =
=D8=A7=D9=84=D8=AC=D9=85=D8=B9=D9=8A=D8=A7=D8=AA =D9=88=D8=A7=D9=84=D9=85=
=D9=86=D8=B8=D9=85=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=D8=A9.<=
/span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AA=D8=AE=D8=B7=D9=8A=D8=B7 =D9=88=D8=A7=D9=84=D8=A5=D8=
=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D9=85=D8=A7=D9=84=D9=8A=D8=A9 =D9=81=D9=
=8A =D8=A7=D9=84=D9=82=D8=B7=D8=A7=D8=B9 =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D8=
=B1=D8=A8=D8=AD=D9=8A.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=88
     =D8=A7=D9=84=D8=AA=D8=AD=D9=88=D9=84 =D8=A7=D9=84=D8=B1=D9=82=D9=85=D9=
=8A =D9=88=D8=A7=D9=84=D8=AA=D9=82=D9=86=D9=8A=D8=A9 =D9=81=D9=8A =D8=A7=D9=
=84=D9=85=D8=A4=D8=B3=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=
=8A=D8=A9.</span></li>
 <li class=3D"MsoNormal" dir=3D"RTL" style=3D"margin:0in 0.5in 8pt 0in;text=
-align:center;line-height:normal;direction:rtl;unicode-bidi:embed;font-size=
:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span lang=3D"AR-SA" styl=
e=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quo=
t;">=D8=A7=D9=84=D9=85=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D9=88=D9=86
     =D9=88=D8=A7=D9=84=D8=B9=D8=A7=D9=85=D9=84=D9=88=D9=86 =D9=81=D9=8A =
=D9=85=D8=AC=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AA=D9=86=D9=85=D9=8A=
=D8=A9 =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9=D9=8A=D8=A9 =D9=88=D8=A7=
=D9=84=D9=85=D8=B3=D8=A4=D9=88=D9=84=D9=8A=D8=A9 =D8=A7=D9=84=D8=A7=D8=AC=
=D8=AA=D9=85=D8=A7=D8=B9=D9=8A=D8=A9.</span></li>
</ul>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span dir=3D"=
LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;=
serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=A7=AD"></span></=
b><b><span lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times N=
ew Roman&quot;,&quot;serif&quot;">=D8=A7=D9=84=D9=85=D8=AD=D8=A7=D9=88=D8=
=B1 =D8=A7=D9=84=D8=AA=D8=AF=D8=B1=D9=8A=D8=A8=D9=8A=D8=A9 (5 =D8=A3=D9=8A=
=D8=A7=D9=85):</span></b></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><b><span lang=3D=
"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&qu=
ot;serif&quot;">=D8=A7=D9=84=D9=8A=D9=88=D9=85
=D8=A7=D9=84=D8=A3=D9=88=D9=84:</span></b><span lang=3D"AR-SA" style=3D"fon=
t-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;serif&quot;"> =D9=
=85=D8=AF=D8=AE=D9=84 =D8=A5=D9=84=D9=89 =D8=A7=D9=84=D8=B0=D9=83=D8=A7=D8=
=A1 =D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A =D9=88=D8=AA=D8=
=B7=D8=A8=D9=8A=D9=82=D8=A7=D8=AA=D9=87
=D9=81=D9=8A =D8=A7=D9=84=D8=B9=D9=85=D9=84 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=
=D9=8A.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=86=D9=8A:</b>=
 =D8=A7=D9=84=D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=B0=D9=83=D9=8A=
=D8=A9 =D9=84=D9=84=D9=85=D8=B4=D8=A7=D8=B1=D9=8A=D8=B9 =D8=BA=D9=8A=D8=B1 =
=D8=A7=D9=84=D8=B1=D8=A8=D8=AD=D9=8A=D8=A9 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=
=D8=AF=D8=A7=D9=85 =D8=A3=D8=AF=D9=88=D8=A7=D8=AA =D8=A7=D9=84=D8=B0=D9=83=
=D8=A7=D8=A1
=D8=A7=D9=84=D8=A7=D8=B5=D8=B7=D9=86=D8=A7=D8=B9=D9=8A.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AB=D8=A7=D9=84=D8=AB:</b>=
 =D8=AA=D8=AD=D9=84=D9=8A=D9=84 =D8=A7=D9=84=D8=A8=D9=8A=D8=A7=D9=86=D8=A7=
=D8=AA =D9=88=D8=A7=D9=84=D8=AA=D9=86=D8=A8=D8=A4 =D8=A8=D8=A7=D8=AD=D8=AA=
=D9=8A=D8=A7=D8=AC=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D8=AC=D8=AA=D9=85=D8=B9 =
=D9=88=D8=A8=D8=B1=D8=A7=D9=85=D8=AC =D8=A7=D9=84=D8=AF=D8=B9=D9=85.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=B1=D8=A7=D8=A8=D8=B9:</b>=
 =D9=86=D8=B8=D9=85 =D8=A7=D9=84=D8=B4=D9=81=D8=A7=D9=81=D9=8A=D8=A9 =D9=88=
=D8=A7=D9=84=D8=AD=D9=88=D9=83=D9=85=D8=A9 =D8=A7=D9=84=D8=B1=D9=82=D9=85=
=D9=8A=D8=A9 =D9=81=D9=8A =D8=A5=D8=AF=D8=A7=D8=B1=D8=A9 =D8=A7=D9=84=D8=AC=
=D9=85=D8=B9=D9=8A=D8=A7=D8=AA.<br>
<b>=D8=A7=D9=84=D9=8A=D9=88=D9=85 =D8=A7=D9=84=D8=AE=D8=A7=D9=85=D8=B3:</b>=
 =D8=A5=D8=B9=D8=AF=D8=A7=D8=AF =D8=AE=D8=B7=D8=A9 =D8=A7=D8=B3=D8=AA=D8=B1=
=D8=A7=D8=AA=D9=8A=D8=AC=D9=8A=D8=A9 =D8=B1=D9=82=D9=85=D9=8A=D8=A9 =D9=84=
=D9=84=D9=85=D9=86=D8=B8=D9=85=D8=A9 =D8=A7=D9=84=D8=AE=D9=8A=D8=B1=D9=8A=
=D8=A9 =E2=80=93 =D8=AF=D8=B1=D8=A7=D8=B3=D8=A9 =D8=AD=D8=A7=D9=84=D8=A9.</=
span></p>

<div class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"margin:0in 0=
in 0.0001pt;text-align:center;line-height:normal;direction:rtl;unicode-bidi=
:embed;font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=
=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&q=
uot;serif&quot;">

<hr size=3D"2" width=3D"100%" align=3D"center">

</span></div>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;line-height:normal;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;=
font-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR=
" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quot;,&quot;ser=
if&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=9F=93=9E"></span><b><s=
pan lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roma=
n&quot;,&quot;serif&quot;">=D9=84=D9=84=D8=AA=D8=B3=D8=AC=D9=8A=D9=84 =D9=
=88=D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=81=D8=B3=D8=A7=D8=B1:</span></b><span =
lang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&qu=
ot;,&quot;serif&quot;"><br>
=D8=A3/ =D8=B3=D8=A7=D8=B1=D8=A9 =D8=B9=D8=A8=D8=AF =D8=A7=D9=84=D8=AC=D9=
=88=D8=A7=D8=AF =E2=80=93 =D9=85=D8=AF=D9=8A=D8=B1 =D8=A7=D9=84=D8=AA=D8=AF=
=D8=B1=D9=8A=D8=A8<br>
</span><span dir=3D"LTR" style=3D"font-size:18pt;font-family:&quot;Times Ne=
w Roman&quot;,&quot;serif&quot;"><img width=3D"32" height=3D"32" alt=3D"=F0=
=9F=93=B2"></span><span dir=3D"RTL"></span><span dir=3D"RTL"></span><span l=
ang=3D"AR-SA" style=3D"font-size:18pt;font-family:&quot;Times New Roman&quo=
t;,&quot;serif&quot;"><span dir=3D"RTL"></span><span dir=3D"RTL"></span>002=
01069994399
=E2=80=93 00201062992510 =E2=80=93 00201096841626</span></p>

<p class=3D"MsoNormal" align=3D"center" dir=3D"RTL" style=3D"text-align:cen=
ter;direction:rtl;unicode-bidi:embed;margin:0in 0in 8pt;line-height:107%;fo=
nt-size:11pt;font-family:Calibri,&quot;sans-serif&quot;"><span dir=3D"LTR" =
style=3D"font-size:16pt;line-height:107%">=C2=A0</span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CADj1ZKnkeNnGg8A31muTUJRsWd07d%3DMSXazgmOf3FVvEMLADgg%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CADj1ZKnkeNnGg8A31muTUJRsWd07d%3DMSXazgmOf3FVvEMLADgg%40mail=
.gmail.com</a>.<br />

--00000000000015feed06428bd467--
