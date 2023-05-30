Return-Path: <kasan-dev+bncBCF5XGNWYQBRBWX23GRQMGQEKOUW6DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id B9B8D7170EB
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 00:48:59 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-75ca16028f4sf378842285a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 May 2023 15:48:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685486938; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBxLPmC1mrbJRLJMzmM7UOhl1HFcv8igvryOWgqokXX9lm9roQeNh8lVBcNIU14DPI
         aO9XctMKL4uHPhe6BRqOJyDu1+1roscrpD6vKomEG0D/aDf+L/VXv6jN+5vr+kMnPtu7
         0TkulQMmddfgVqpErIrlDL8qKr4hXb8DjbD3WWEDVuS8/RIlaQs8I5MMwrHUnCMmgflP
         bjgjbTa+Mw1qV+NagqxtaGKgg0jmMdW07F80s4aNJZjh9/p/qP+garrzIWfMjicbytoK
         +NeQhlX2/2mvGdm8Q3OCoPwR/tV2VyLnBF4vxXy9Rfu7ycf8HikY8dNoDwUlOba6Q+if
         RVtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HPaEcfm84hK8ckE6qnDOq/eEjEy9cCEpKKNVvhuTLHQ=;
        b=ra8z8QjcuU3TaTQCEmgwqlWMO+ZAbrhXwa/ACPIP0CDLDkAL31ajdTC6h9RAU9bJfM
         dE1FXPUZ34dblp1GwQd16byCr86UDLQX0NEhKPk+L+aSuVbiDlzSoayGimr2f89lHv1k
         ivDtLmujO28ch2zlravxMBXIwakxfnjD9/F5QFZG6+dyoTq15pigEA1EbRWabegr6ZhS
         yj8rL9rEn2S3qGGd/zhDx2Cc21gtlZnhh1ghNGxjzVdaaDEf8Nxur5se9JXAKym9jEMT
         JAeZcpIsWqOm2Mt/gBUqvEsfbt/1goLpR0CuQUSmqVHoxFTvdrrHQL0cPagxFuz6D6gf
         0jWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KVEG8WOB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685486938; x=1688078938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HPaEcfm84hK8ckE6qnDOq/eEjEy9cCEpKKNVvhuTLHQ=;
        b=Biu2Anjn+i2IlyFl8zZOGbgvf/Xw6f4JQcBZaQbWEJBGKcGO1CjoS5PC/FNPuOlhsE
         SSNaveBQ3esqD0NUZCuAfhZwKzypUzEBanbhNISL95OF5AXZQq+4THvAwZUQRHk9ZT6w
         Zk+ZFfxVOqcvGWeP29KfDOYrU7G0t16bKdnV9KKo8ag1eFutDxmn47FEIJhYmr1jfLHD
         oC6i8GXlR3FYHP+QhWVlg+I2V+GBYz1QcUrx9UkY78NgKlOFbJRsBdjnGY82db66lvO2
         iL0M1kiQxd1C8x3HhtALRypUHqZXEoVk7Z3k7XGBOw59DaKef0uK7iMe2VH93zG34jxg
         cSLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685486938; x=1688078938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HPaEcfm84hK8ckE6qnDOq/eEjEy9cCEpKKNVvhuTLHQ=;
        b=SOb6E47qkTYugT2DxhiqH2NMPhpX30N/3wUGX0gmhNjydKTYvPiVz4TtInRuGBWoTV
         IhCHE90tWnAb7fHKPQ28sg1wcTwPsoJSeC/ta8NEoAou0G/mPnZZwqp6hId8tPOxOSYT
         5NmqZDl4x9G0ORWRYYbbzCauJwSA4OGy9YxmWHKSfDY5OYktzs1dJpy4lbhHmFrzvAlU
         J/m9kfaLAtW+IFklhj6DfhlO7SZkadBIKzH8SujInLWTZfn0yHrV+nT012ZVWY44S7t2
         FrhWFLSY0vJzbWaNmE2gsGOWFe74QAMlu/Cria1Ag7RzRbJY19ori1GRy9ZNd2IBdN3/
         iFhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzREyZ1JN3uDGGTz+hMcollVDLOkAXljyrBkZx7I62JWwpO88gP
	JKs/kKSpB63m/JLDJ+T+Brs=
X-Google-Smtp-Source: ACHHUZ6a7CshZeJFKjo4KGw+09CAj+B9cL9Vq57DWboGjTELRWZUw3EIXrVlzxLQ4B0PBXED+ke1hQ==
X-Received: by 2002:a05:620a:468f:b0:75c:9881:18fe with SMTP id bq15-20020a05620a468f00b0075c988118femr1072165qkb.1.1685486938260;
        Tue, 30 May 2023 15:48:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:14f3:b0:623:8497:1410 with SMTP id
 k19-20020a05621414f300b0062384971410ls1043124qvw.1.-pod-prod-02-us; Tue, 30
 May 2023 15:48:57 -0700 (PDT)
X-Received: by 2002:ad4:4ee7:0:b0:626:9e7:7347 with SMTP id dv7-20020ad44ee7000000b0062609e77347mr3678802qvb.55.1685486937746;
        Tue, 30 May 2023 15:48:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685486937; cv=none;
        d=google.com; s=arc-20160816;
        b=QFzkXM1EqmXSRc6NnMTqX0JBXuFhRGfw8acageDiMbHzk6q8LYWYg85oTzngJqWvl+
         O8qwJ0td7jHIyz9cawBJ0/PI8Jd9/UDa7AFIdEbGILLxguGvPt7LFvIPAujmzb0Py6BS
         6LQ1aShczrO4xHxjvPuTR1D7mj22LCQdyam9oTPIuOh4IgS6J4V0xOrY4oX7/afvyoIL
         /5wI7ZV0sHhvCyv516ZozzCLavoeSB7YAppBenPb9DHVJHDbbLOYPViRrXxCP00XPQJJ
         rIecA8deq6ZuinrhOKT77lPeoJoZ86/9LTY3tCH74gtWZF+MiP/JdYTVVYZnx6zLiEwb
         HdLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HVPCrHupYIDGk/MKCRILujiQNCUeyrDJevz6XX+Usd4=;
        b=hfCDkbPHUmL1akEm5sXm7x5/0rzsYCgIh2KzBj3kAJ5yT/wwLfMRd441xtM+gknk6d
         NZl5Kpo74DjNyshJ+Qa/ZhW5HUtj6Uuej/GEIGETMwtJqFlyF9DVQNN/8sGwMD8CDH8v
         7aZLo3ja8Ui2fEG+LY+bPuBRFHKhyC5FcYUXyI4lpVc181tUNb0d8d260y2aXWlCS9l+
         RxZgzQSXdaxZGtdbbOs6Gvxo5M1OAxn4yV1Q2fHAiursT1+2FJq0ASvpwrxQkieZ8u3g
         mKRAzrrv6WwsOqj+kVVRiwzQyHT4akqFBQrgmA0VMSXQgoGmCAaxDrn61SR+2CdBo3E8
         xt+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=KVEG8WOB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id b4-20020a0cbf44000000b005fc5135c65csi1136654qvj.4.2023.05.30.15.48.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 May 2023 15:48:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-64d341bdedcso3705870b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 30 May 2023 15:48:57 -0700 (PDT)
X-Received: by 2002:a05:6a20:2d2a:b0:101:e4f3:5336 with SMTP id g42-20020a056a202d2a00b00101e4f35336mr4090246pzl.27.1685486936857;
        Tue, 30 May 2023 15:48:56 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id g3-20020a62e303000000b0064fdf5b1d7esm2084298pfh.157.2023.05.30.15.48.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 May 2023 15:48:56 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: arnd@kernel.org,
	kasan-dev@googlegroups.com
Cc: Kees Cook <keescook@chromium.org>,
	peterz@infradead.org,
	ardb@kernel.org,
	maskray@google.com,
	mingo@kernel.org,
	mark.rutland@arm.com,
	Arnd Bergmann <arnd@arndb.de>,
	linux-kernel@vger.kernel.org,
	mcgrof@kernel.org,
	quic_mojha@quicinc.com
Subject: Re: [PATCH] ubsan: add prototypes for internal functions
Date: Tue, 30 May 2023 15:48:55 -0700
Message-Id: <168548693422.1303000.13322516962032319887.b4-ty@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230517125102.930491-1-arnd@kernel.org>
References: <20230517125102.930491-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=KVEG8WOB;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, 17 May 2023 14:50:34 +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> Most of the functions in ubsan that are only called from generated
> code don't have a prototype, which W=1 builds warn about:
> 
> lib/ubsan.c:226:6: error: no previous prototype for '__ubsan_handle_divrem_overflow' [-Werror=missing-prototypes]
> lib/ubsan.c:307:6: error: no previous prototype for '__ubsan_handle_type_mismatch' [-Werror=missing-prototypes]
> lib/ubsan.c:321:6: error: no previous prototype for '__ubsan_handle_type_mismatch_v1' [-Werror=missing-prototypes]
> lib/ubsan.c:335:6: error: no previous prototype for '__ubsan_handle_out_of_bounds' [-Werror=missing-prototypes]
> lib/ubsan.c:352:6: error: no previous prototype for '__ubsan_handle_shift_out_of_bounds' [-Werror=missing-prototypes]
> lib/ubsan.c:394:6: error: no previous prototype for '__ubsan_handle_builtin_unreachable' [-Werror=missing-prototypes]
> lib/ubsan.c:404:6: error: no previous prototype for '__ubsan_handle_load_invalid_value' [-Werror=missing-prototypes]
> 
> [...]

Applied to for-next/hardening, thanks!

[1/1] ubsan: add prototypes for internal functions
      https://git.kernel.org/kees/c/d25ad53db59e

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168548693422.1303000.13322516962032319887.b4-ty%40chromium.org.
