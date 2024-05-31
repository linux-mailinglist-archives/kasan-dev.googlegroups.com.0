Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOMB42ZAMGQE7EEMR5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 211828D5BC9
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 09:48:11 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1f60c044420sf15421775ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 00:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717141689; cv=pass;
        d=google.com; s=arc-20160816;
        b=FLFxRV5MgbqkjvA0SfOQOFEqzUL4ppQbmWqQoiwTkCy0m0ySSMxc+MT7wS6BxWj0+f
         OmfabMHzFh12D7OHQSYnp2iumjuDhGM+gXsOPBl1Hz1/Ogoh4TLhrDERXCCe65LY5gYE
         jYaQ+kvrZ4KJIVxnTxs0uWaJC/3GLCGTTB1XIW59j4Fky5E9t/U93rc3IaSPXVzL55QC
         HNkWwwkpcAihiy+ITdpE7ddILVCVz+H5mE5glQh+OtyEIU1HHgpgFl7qSfsGxyidcfgy
         ykEww9KiwlekwprjRv7wcG7/tw2EIupks2x153EsKHqBViMXDmwM8EGgMh5RNsRc+l4b
         fW2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e0YjiSGEcCUj5CBA8BLTMXgPleFhpAK1YhIf17KqEFk=;
        fh=n3xXrM42+mMJ5yVl+8czk/jq3JQHDL9z53Fvo2B0SXU=;
        b=oJwNQdKtvZX5wRA9apRickde9r0K1PSIeG8p/1iAtwTfnk1uoBG52TZRf+FKDNnrvo
         +o15a4V6xyViNFmJWt2edsC6LC/Q7UtqGiY4d4jNsWZb/n8Sk8ohsnEERbVPNW3gqEuE
         DuRXOIYNUXMiVj4ZKxe2Ky1DvK622dZg+cvvmF4LJ+Qgh4JPAcHQCKCBFhRqKoJV33Gw
         EjI4s2TmlonHqxcKEDhyz0KhqeKcqqfwIIoSkCXESYmmJAEKWE6dJVDDUkWYwuDJnyUf
         IBa4n35L1I3m/lq13ExQtizGs+3WpSUKsVk6hn5xcpvOb69r5WRWeyYYkKuFGpi4seL2
         wF3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ncZb22dT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717141689; x=1717746489; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e0YjiSGEcCUj5CBA8BLTMXgPleFhpAK1YhIf17KqEFk=;
        b=NNM8alX5zUyff/EcSuXVPvcVw5ggquKixYRGgqA3iSwtuJrf2OUpbaLwa3QNyw75N8
         Au+LWJx4bsrh+nKMVaxmg4vwlGMlyl9EqZCPmTcCMwTZRCupYi6oPSNT0Q7vjfDldOeY
         YuaHhK+7yFHZVn8k7z8u+SQYgfH+9Nunizntuj8Zb3upvrap5m1SfDrE2WScpjLP+Fym
         jfJDTQjA5nrLVVdxk14zuQ/3q8GVPiXhaZT3EWrrS1gnXVAe2twYfofsblsJ4snAiqFu
         iLA9Wkb4xr33lG0efvXSmUD3GUE6qa7CQKrid8Yhr/Dut2rMdZATqQx0idFSOtgpEeGm
         9+ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717141689; x=1717746489;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e0YjiSGEcCUj5CBA8BLTMXgPleFhpAK1YhIf17KqEFk=;
        b=s3ju2YNJidEPQcWkmMOVyVFXuHyulnYZ98l/HKg9aG/votyCSX0oPqbGBJHnlYsLV8
         /Ac/edBRrYq5oQCSpoogAFHhE3UohC4DD5a8F1090CkMGjJFDJt4oA/KR4SOj4bJWaXz
         2rTr3Uy7cUlZkgdKijurEkwyMMTLqxqk7k1U69WGGWpGWqATMzjUs8qLzPJSoe+/SBGJ
         FBtiOs6VQXKSVcK3WAvJIO84mq9WsS0VHlAjON6MRYVEhJmRTi/tBHQ6dBbG3hYeZdec
         RQWHblqj07wrgEBdR5HvyJX3dhjXE9NJaAi/x/WJzCD2th+alK8rFHrM+C0CuVmnbR9B
         BdIw==
X-Forwarded-Encrypted: i=2; AJvYcCVG1LAnEMNmPEdBTtShq5762Th6r5UobtUwubAIB5rxZ6rhZQYN+71l0ji2N1NAwDGofLRSRjN4UGfUDpjw3nU1BRTI44hlEA==
X-Gm-Message-State: AOJu0YxvKrUolWldrr7htgtpDL/+CpP6wrL6jG3GMq0GnO2d47Hg9LtA
	WiYgI9BzSZo6rHyD/7GXpC0tuSFKg7vasybu/3qImXZbFP05Z04a
X-Google-Smtp-Source: AGHT+IEzxcVNhPnHaDtPOAFvqbZCg8FPQpSSWcjGb9Yd1g1FkZzqnmz42T1dan6KwhFR6DbPfu3m2g==
X-Received: by 2002:a17:902:bb96:b0:1f4:4617:fc72 with SMTP id d9443c01a7336-1f636fefa75mr11239345ad.17.1717141689252;
        Fri, 31 May 2024 00:48:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32cf:b0:1f3:555:b70a with SMTP id
 d9443c01a7336-1f616f943e1ls9744165ad.0.-pod-prod-09-us; Fri, 31 May 2024
 00:48:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYNGLMSgH6VYwH33U8/qcBbfcDt6+/Gs7y6iCNG/EQ60zyxKKBZYS9H/T15NhwyEyZWkSfjQXvOj6GDe96k3D+SAEFINVZ3/7/LA==
X-Received: by 2002:a17:902:c942:b0:1f4:887c:e3db with SMTP id d9443c01a7336-1f6371294ffmr12932015ad.38.1717141687894;
        Fri, 31 May 2024 00:48:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717141687; cv=none;
        d=google.com; s=arc-20160816;
        b=tFsesN3leoqk4svIhYxi+WsE1zVebojTtL9Tbl1J1qp/8rrRWT3FyaV+NkZUsJ3sMv
         hJcGAabheAED/tgwAGGP5R3OypfVWPg1ahRZlTOJKz8t+RPRg/0XfS1K6isbfvDB80ew
         z60XujX1WZi65JDsaacMZ9Q7g1tjgkI4EFFY5u+nXIX4N4MjsNTvpqFlx3yHfw/F7NER
         Trnqm2li1MD5Pl4K+mo922svSvF9hTqhsFXRnz+m2RQWZGZZMaCQIXX7So2F/kI0lEdY
         /MsZqOUGUzab+aI2p1xe+C5HOpzNKlBZ6ZkNE27Z40lv1pUBwSFkC7HjOrOwDub04jrs
         H19A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aSaCVUi0zQXquWS21+Fh+LLppuApoIxo0HCn/IZS3vI=;
        fh=r3gqH1Jal6VO0Dc0aO5SYPIExeO21KsABxbhycH0B0Q=;
        b=drlJEBX/CjyjY8SH31VvPgV6xl6En9VrrAZThxFU3UrEW2KKOpO99vFPkvCr7PESA2
         Fy7L2RwxEqbSjtoQZWO6Q01OG3afAMf/dKPuXY3cZL5HsJOSZ8NlNCArmf1egYqUIZ3Y
         Sx4jwQ8C2p86es/f2v74i3/uYX1YRamVHthaUQO2RF4mtsHSrv8BuIFL29Zsul56WhQ6
         bvxKsmAcJaRSKr5snvzyEE6fCDb7x3JksMux5f4Vp0yanI373XK7uGp6HjeG8hM/scV3
         UvZ2DvFOYT5H5YezvpmkMgIpkqhpVw4rDIvMXgcgq+yoB4U4NoTfSGn4ydd1A8ftTO8X
         bHGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ncZb22dT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f632379b6asi623165ad.7.2024.05.31.00.48.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 May 2024 00:48:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id a1e0cc1a2514c-808c613ade5so592135241.0
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2024 00:48:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUxXfQeIhSpJkClEZubdr0dXf2rj+064QY8qgZKL8w/YwumQQI3Al1Sw2kYnJIE3kz6ZTVNIdUE33NQ3nlQBg2pemS6jU2GuQVgYQ==
X-Received: by 2002:a67:f655:0:b0:47b:a00c:4680 with SMTP id
 ada2fe7eead31-48bc2370c46mr1125258137.32.1717141686612; Fri, 31 May 2024
 00:48:06 -0700 (PDT)
MIME-Version: 1.0
References: <20240530-md-kernel-kcsan-v1-1-a6f69570fdf6@quicinc.com>
In-Reply-To: <20240530-md-kernel-kcsan-v1-1-a6f69570fdf6@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 31 May 2024 09:47:27 +0200
Message-ID: <CANpmjNN1qf=uUnetER3CPZ9d5DSU_S5n-4dka3mDKgV-Jq0Jgw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: add missing MODULE_DESCRIPTION() macro
To: Jeff Johnson <quic_jjohnson@quicinc.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kernel-janitors@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ncZb22dT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::933 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 30 May 2024 at 21:39, Jeff Johnson <quic_jjohnson@quicinc.com> wrote:
>
> Fix the warning reported by 'make C=1 W=1':
> WARNING: modpost: missing MODULE_DESCRIPTION() in kernel/kcsan/kcsan_test.o
>
> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>

Reviewed-by: Marco Elver <elver@google.com>

Jeff, do you have a tree to take this through?
If not - Paul, could this go through your tree again?

Many thanks,
-- Marco


> ---
>  kernel/kcsan/kcsan_test.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 0c17b4c83e1c..117d9d4d3c3b 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1620,5 +1620,6 @@ static struct kunit_suite kcsan_test_suite = {
>
>  kunit_test_suites(&kcsan_test_suite);
>
> +MODULE_DESCRIPTION("KCSAN test suite");
>  MODULE_LICENSE("GPL v2");
>  MODULE_AUTHOR("Marco Elver <elver@google.com>");
>
> ---
> base-commit: 4a4be1ad3a6efea16c56615f31117590fd881358
> change-id: 20240530-md-kernel-kcsan-9795c9551d3b
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1qf%3DuUnetER3CPZ9d5DSU_S5n-4dka3mDKgV-Jq0Jgw%40mail.gmail.com.
