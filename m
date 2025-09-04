Return-Path: <kasan-dev+bncBDP53XW3ZQCBBNXJ47CQMGQEJC7NRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id AEF90B4472E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 22:21:12 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-24c8264a137sf18821615ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 13:21:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757017271; cv=pass;
        d=google.com; s=arc-20240605;
        b=VHCwqWSuWQEae54s2IESb0NNNZPpexUwwAM8VWD31Ole8cvywyVyIfjjMMOmkV/RtQ
         O+J+vaFLmkIaZv/CFf4YTrgwYXFUV+BiVaCCxykJoKQ/85LwwNG9VxtBi6z/fj22cvPP
         eR7bxL1nyyf+F50yWFLngBq1S/3Q5aZOUVuQCX1k3ZoEdarAYwVHcWi7Oe4Iiyh2uOXa
         L8OkUKF0CLVGP7RN3bS+ZugHo3fSpIHNNzQ++UacQvICCgek14HECbFpGHl2hDQiSLfJ
         BwTWC9WTmJ6BBiYni/3Q8cvtkQezMIBlyFcCXD9rpbAeEonN92UPPq2HNK1IuO0yfYt1
         NyBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=sANKoRVQWX31LYz59dZ6SOp14sjoc5aMtFkGimfM3l8=;
        fh=x17y8sbEYvrEekbeR45uRBE4g0POQiobIDN8ocMJumA=;
        b=d4kTgDC+4b6phZoT/EYUWvTqDXnXaY+pqhLqQ6IPXLqmZa0p0ofViujryiYy/pLg5z
         9HVjQj8rt5KKGzLkhvibKIKEcgFcffukGAgt3qoo/eYD//wackg89gMqtz7UMNY7LsOI
         u54FmzdmaQ2Ze85sQpB+Zd/CBwShKktaqfeZpdwllUnYTUAP+pwjP+cnGycH8AHqUpxC
         I22oD29zWo7bEqNGvTN4cIaLw8ZK87oCThjtOR2T4FFWymsWsHb1Tdgv61F5I/D6JmTy
         NY5tWD4JsUsohgNl68/1neFO6CrD9a2FCYJcs6GEA8oRbGldlX9QV6R4oY64wY/k97vw
         o3wA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=it5BPxKR;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757017271; x=1757622071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sANKoRVQWX31LYz59dZ6SOp14sjoc5aMtFkGimfM3l8=;
        b=NCmY7AztRN2rjZ1KpVuO6PQ42ULEcA3TRhsbdYRbRuTwSYkxdhDZkk0ScOnRBxoiPM
         Eo93Bw3EfNiSMZCk+Y+duOhgnGzZA+8ztj4r/bI1zQDBCBPTfrE2hMzFqL552ST3VDfc
         tsjJXs3ORyijFlrDNsPbAsZQFznA4Owub79e8mbdWINF30LNyC7AaHvwqver3UdGG2Hn
         IgWOS7QSNixeWSOM8Tlw6LHCOWI2AD11UTPBoQGqQ+BDoPZkW0IxSWsbOfzYrq4qM7K0
         5c9Ak/th6eQLunh8plvYCzytjqQoTePsmYKi2ndPlNmClDPXQi9Vadwz7g2pmGKGVIwE
         c71g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757017271; x=1757622071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sANKoRVQWX31LYz59dZ6SOp14sjoc5aMtFkGimfM3l8=;
        b=fNxtmxd4vGfPOL63mMM2V2g5jgUX59Ror/NTi00oMqe5Htbp6MhDaqlBLdk2LV4J4Q
         jY7VzZE8+iIZOelub7Qb6ehbexOTBuLRbqYyQ1V0wlSAZNxCm6W9VYRqZTp2TAwLLm43
         28L0BbylVmVbx2cCg9tyvPF0HyolHueyny9WqAIByw7haw1vXiwSTT7y0xrDOH1BYprQ
         7SMZ1xDFEyH57U+lqapo3LF+wtusE5BwFoIRjDtGvpTZG+hKoRbhe79YIV0T4GnJfsEQ
         yvk2vqNNhTCOR16kVCzTUtGelHXBkXCFBQjUR7cdHqSKVqQYtf/MQbaTfBBpTuYOeNW0
         wqdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757017271; x=1757622071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sANKoRVQWX31LYz59dZ6SOp14sjoc5aMtFkGimfM3l8=;
        b=YJDGEPerwOcBeJBuWzcBqYhVPY4YztNCXbJ7EgBQgwbjKoh2PZ7STtLXZ2BJ7DPwsH
         ztekC/JlpVV9hO17T0jKgmd4C6YCgm9k8sekR8yJ2lcgTlG7retJ4zpYeyzTIMaOHv82
         pyb0KAvtC7cb2XbOFtr5zT120hc/3TWB1ZIxb32CQJI3z6t+dAi1k2YXV0XRfLeXHu7T
         xIMlIU1JctZ6jpKhyryEvirBr7O6PefMpAN7WNc9WDMcEtRuKpGeQosvSMz4l27emiWn
         G+wzTvldsNmXwo8ojYOcRj+pzW3wNaZrikj7tq/MZGyWjp9tQZYwPrX2yXLzY0TUbvGO
         dVrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWh426y1+6KRdpe8a7rvwm/5tsjelljlIwovgItONHZkglE0Xv9zdUyD3cMHhxM3nuFAOiycQ==@lfdr.de
X-Gm-Message-State: AOJu0YzGByhpT1rB6anmoETM1VSwmtBe2ZQMvU6+zH5BKgUvcs90RJgq
	32U48bmEd6pJ0/pdpMsRhuAKyIIUt+jhyHuPTpCrtHuOb4k+TzuDrb8e
X-Google-Smtp-Source: AGHT+IFaSLulU3ExB7ygOQkjo+Pw/3dRU6EvpCAtiMavb/6ntljsNIWpncp8punlYkKlqkOn7Kz85w==
X-Received: by 2002:a17:902:d490:b0:24b:15b3:224f with SMTP id d9443c01a7336-24b15b34b19mr153099915ad.0.1757017270666;
        Thu, 04 Sep 2025 13:21:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf4nQyUt9Vp+6Pnk1S+IC2T24llAvJpYfbXC2fNqSly5A==
Received: by 2002:a17:903:2c06:b0:248:87fc:1545 with SMTP id
 d9443c01a7336-248d4b1b733ls82943755ad.0.-pod-prod-01-us; Thu, 04 Sep 2025
 13:21:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTsjR/WmukGTT32BGcvZ/UQIuZM3fM508xIRwk5nW6JIfh1LmsP15ryuSD1JAmrq/Z2/C2RtFuRLw=@googlegroups.com
X-Received: by 2002:a17:902:e744:b0:24b:1427:1783 with SMTP id d9443c01a7336-24b14272522mr144435245ad.32.1757017269004;
        Thu, 04 Sep 2025 13:21:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757017268; cv=none;
        d=google.com; s=arc-20240605;
        b=WG1sU/WWB8LkXj0O3IJaLu6A1Py9diZDDLst/bizTCID7904x940m+h2dcb4FUv7Rj
         jpIVcs60jj8j1d+09yoapmoPgYNLPv6MCnzXARVf7G8NSird4rWtyroglHp8+hNWsftu
         xOAdhMTJfYN/6eI2OzUfScO8CmMI99NQNzxmoYZSvgtIdQeclGuDCpGVRKuvKAyXCtjA
         KijWnvzX6WiHfkCHDs5ka2JbWo43PBFVb3Fb50s+kUqqoAIDsIqXNVX65BqzzXQrl4B5
         GNmbNQMLvuzqisCuW9fvb/8OjnKIirHA+MlNTENchNzOUZZcC0YNLqp2Wk9R/oyAuNbV
         FgYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5R73QwFGpxpwtcDAq2/wRoOXZRZTM7agVtz97/zJueA=;
        fh=nzcihl/xfyzislZhJv7m/4HKjUldZxKhC6nzd41TXZY=;
        b=LsjBNFERXmSYlEoHnTwVXSmZCrdOeBEy2c3rIU2VVBjVRRyN0wP/5RlzXYjgokeXjz
         0mrYn8KVk0SpfHMd7lGoJuBXS2zhFOUI2uxoXAHqqL47m75BMNDbldERlgRXi/DWYKNu
         sCzpiJ25v4pMLiAjuaCvjKk4fH9fzE2/mOAtEn3TsXMFl3ahSsdTdwZa3Su+dJUcjuU5
         ++6KV5yzdNqGxbiw0gCvpm1b4p7Un0JtonnTtfeC/UTpXVXsVP4yMv14Vfjn1aTHJWJ7
         PsJb4+cb5fYUsc5J03lSAYSs178N9HJjCl3S41t483BqwYvhYhG+5VlJZDVaSP9VRGaG
         /l6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=it5BPxKR;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24ced9fc586si326605ad.3.2025.09.04.13.21.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 13:21:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-24cdbeca71eso5573175ad.2;
        Thu, 04 Sep 2025 13:21:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgVYFB4XIXEcgg9g5xN7119b+oj7Hr23YEbc1UCrrzUnTDBVL8E6+BoTNYqIwfK/SvCwYJLS/aKJc=@googlegroups.com, AJvYcCWi3X4VOS0m1VU8Jsf7b8F7RYhD1LCPAWLJlcBhfYj3fsQD1FMUX4Jt0qD6F/5qu5OJEHLlzHmUDmni@googlegroups.com
X-Gm-Gg: ASbGncv7Nl/dbq981PMxJPO2tQdyOOV+cEafhVzqei8LBWnoOHwNI5JLwq7sPexd/j6
	BY3yxvRaCuri48pYYrQnN9IZfujUJDy1OYqldsM71fNXRkkIcpZew+MJai6BisoiSe+ezdJNgyk
	7+mA/s8XQ1la9Sb86aYPXcST08Lek1lHR1u66pu2sqpVcVX1mLbnB0OQCajFbeSNBFTqKY2XEMv
	Jc7NXJpe3p2/FzIZbTtHyawND8LVWMFgDeZcQ==
X-Received: by 2002:a17:903:37cb:b0:242:9bc6:6bc0 with SMTP id
 d9443c01a7336-24944b73618mr268496855ad.55.1757017268482; Thu, 04 Sep 2025
 13:21:08 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
 <20250901164212.460229-8-ethan.w.s.graham@gmail.com> <CALrw=nGkk01xXG7S68FggsWQXygTXnXGz8AvseQuRE9K-OE0uA@mail.gmail.com>
In-Reply-To: <CALrw=nGkk01xXG7S68FggsWQXygTXnXGz8AvseQuRE9K-OE0uA@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Thu, 4 Sep 2025 22:20:56 +0200
X-Gm-Features: Ac12FXyXqZdTxVG6TdzkdqBvv0Mcwr4nVECn24stQHwKcyWRqz_jVg7upfdtHW8
Message-ID: <CANgxf6xCfk9uDsGgqWqociv0Q2Ngu0_GBR0vzWHwOAowsO+CVw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 7/7] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Ignat Korchagin <ignat@cloudflare.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, elver@google.com, rmoar@google.com, shuah@kernel.org, 
	tarasmadan@google.com, kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, herbert@gondor.apana.org.au, davem@davemloft.net, 
	linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=it5BPxKR;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

On Wed, Sep 3, 2025 at 10:58=E2=80=AFAM Ignat Korchagin <ignat@cloudflare.c=
om> wrote:
> nit: can I ask for another real example? AFAIK this subsystem is
> rarely used (at least directly by users). However, one user-controlled
> widely used parser terrifies me: load_script() function from
> binfmt_script.c, which parses the shebang line for scripts. I would
> really like to see what this framework can do to fuzz that.

Thanks for the suggestion! It looks like a promising target.

> I'm a bit worried about the scalability of defining one (visible)
> config option per fuzz file/module. Is there a use-case, where a user
> would want to enable some targets, but not the others? Can it be
> unconditionally enabled and compiled only if CONFIG_KFUZZTEST=3Dy?

That's a good point. I agree it's best to enable them all by default if
CONFIG_KFUZZTEST=3Dy. A fuzzer can pick and choose which targets
it wants to fuzz so there's no downside there. My original thought was
to maintain consistency with how KUnit tests are built, but since
KFuzzTest targets aren't executed directly it makes sense to diverge
here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6xCfk9uDsGgqWqociv0Q2Ngu0_GBR0vzWHwOAowsO%2BCVw%40mail.gmail.com.
