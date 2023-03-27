Return-Path: <kasan-dev+bncBDAZZCVNSYPBBD4JQ6QQMGQEDGEL7MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id E470B6CAA94
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 18:30:08 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id d15-20020a05651c088f00b002934e8e57e2sf1987632ljq.10
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Mar 2023 09:30:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679934608; cv=pass;
        d=google.com; s=arc-20160816;
        b=IR2dEkzpCk8l3/ZU5zd3W6Az7F1nQffFtF+GRAy5cUKOqeY3ZlKtryulVKD4mhxCJc
         ZfjDEYHqSX60roC/UYMSukOzNoRvueII/WqBTETcQWGYmOKABNHu40xCWQEc5PvWDRz2
         q8XRzsyiYH7wR/S4zPjC9gh1Cq86cuWShqoFsIpvVqCjb599AHA0JBC6YTFnXZHe4yNT
         SGR93zqxzQRIr8M1i7z4Ykyjn/z07SgigM7/VDIOdgMXQMgXZ66ero2fD52UFazx1w25
         njtNcZ45xRH8Gk47DuJHDydSgQlAz7jb7WSiuGfws26XfYaxsGSW9vfpdGHrSkg9jucd
         ytwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bFgytFiToW5EL/Y5tBUASDkT+XsWB2dn3sc+FW+eOMY=;
        b=SejEmwBx211/0KSeXdX7ROL+WMDVY4wwFN68cTAo2Ez2hFKmR9qF/VsP9rnTAistbU
         CWrf5IZe/gCJtZS8pslAB0d7MsKOyxf4vznH2qngzXt5ElPwrZ9zcwP6LBUeexynP0ji
         VSTUCR63xGnLvL/MYq3nuBjgRB285KaqI8VBj9ZXSucm8Jim/gP9FKFyLQMt4yHIDGk2
         t6Ijhs80v25q7bE+ai0Vkoja+cv9qJnD29djPXDHWhCcKubtoY0HQgUKiPbNvZjWx0V1
         DbRdxsXr8y6sgZrdan5zTmikTf3Wfq6uZ+XIDwCeBRCZGuK6DMUp2dUgP8ygkzTgru2+
         7beg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mirWSre2;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679934608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bFgytFiToW5EL/Y5tBUASDkT+XsWB2dn3sc+FW+eOMY=;
        b=S9T2YrqE3KBG1KRt8fT94p4bJoynmKKSnOcDs3ucAHEL9vn/N7TST3va0FiCtnZuWm
         8i4xrpoZD7rdFM6pIzhBbtXCHfNYOV/e4ayarThu49v+YNGePcWmk2g3KX3/NWa9EB5E
         UPTtCwcrGyz13zJbOXf5HJH8U7dqrXUoLP9HAmW0EZiZwuK/tCgd87d3gfEkri3i3k1O
         hFDFo6KcFXvDJjOZ0yyeWYNwuqvdNtcGPHJGb9F86XONzsUaF1VaM+nxvOTxYt/UUTCX
         PdGyIOEluZlNdUKUWaksv7Nsxx/pbDM0mMJBrtwvm2aHJ5fWNyv+FaHlGy4QQdW10YPr
         OMNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679934608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bFgytFiToW5EL/Y5tBUASDkT+XsWB2dn3sc+FW+eOMY=;
        b=2RDm5Zx9bC9ImKyNwfepH1QK6nMGoIqTA1hirkYxpn1Vgjb1kY3P2NlVBpX+zrbg22
         0jd1zBRH1U5E6fZ0D2rT3mqcnqE9ybaCD1TqYf68sM+3xIcb8yQP0GFZrti5/hL71dL4
         Y2dWMDU9ABG73bTGDYRBoPxOI3z/ekXSNrK/Df0JMO5cFFMF+4elSBx2hsaO7L8lIUFN
         HNPMhvXfrhpWqCCs6ErEHqjVfKCvSWLiyW4K1XFReyWZ+kqoGNiwHg03Ugihck+hTB+7
         UzX0V6e/E8cPXgWQKb/NqieBGjGnH3xgVdSXazHL7Z/J08wSNsJdB7qnRunacJVXhK08
         wTmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9fze5BAvwfvthDa4a4bSuWgfXASQqstXWnSf3TTfoVfhb2JHVrP
	7Y1HuWMRY5yieBSr/dCuJ2c=
X-Google-Smtp-Source: AKy350b6l1n+ctDQs3ttRgQwdNb5v20y0NO5S2v1pXBH7VU1aOe66686eDCFv8O/0XR3HfkM8g3ueg==
X-Received: by 2002:a2e:9c4b:0:b0:29e:fcb3:b37e with SMTP id t11-20020a2e9c4b000000b0029efcb3b37emr3636577ljj.4.1679934608060;
        Mon, 27 Mar 2023 09:30:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9149:0:b0:2a3:4892:d18b with SMTP id q9-20020a2e9149000000b002a34892d18bls1616562ljg.1.-pod-prod-gmail;
 Mon, 27 Mar 2023 09:30:06 -0700 (PDT)
X-Received: by 2002:a2e:8881:0:b0:294:7360:7966 with SMTP id k1-20020a2e8881000000b0029473607966mr3908985lji.30.1679934606660;
        Mon, 27 Mar 2023 09:30:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679934606; cv=none;
        d=google.com; s=arc-20160816;
        b=Q1q+pWkXkhg2dKrMerFk6iGzr/rEW17hEVzGtKd0+PfB6NctEMLuG65tHh7iNRAxX9
         qQez25+BhGZOXLQWvch9NJ9LugTN1jgYFdkLM8Wh07WN646aOR973MbuJaHYi8fJsUuB
         6X813wurrqzGJ9On/PU/uNf1pI1uO6SVm0G5m4luu5QWXW3vgUPjiez3g2M7UxGSgL87
         pijSS9mmlYkCuqFNQ3J/WGGaS5j8FO4vwEQUvldxcfu63VnFoiV6EzgUwxX6t1K9WQC+
         3U6Eax9cq3BIdkVAajSq3LdBp/iJDux+wItMcaQcSc1IuSibH8UKO/JW3hjD95ng5eBH
         H9ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AIpzahNb+oRO4ma6Bmmsk7Fa8/q+bN3MwfUnPQJQWV8=;
        b=yt4DpuawOwaPj6rAk+Ybvu7+y/27wSFtYl4Tqn/6XiuWhwTNOIluMUhu/c78glGKPj
         0RhMKAqYMy1vZzsNRnKTbBVoLDr/EGocnuIZRxLv/s8vqfjnfwsxtBgjZ6YSm/oGCefF
         BQ2HY9NNqWBQSbj6pfdCKvOWEpwUv48oNJf4spLwDE2fuui1IiNz4opMTrcwswXx4pll
         43P5Odb7qxJqLxQuhG5UUcAiEyj36CpbkSS3PMKQOq3JUAT1wTFDOBvPKsM9bLFioHHT
         fNH6PFvTh4GAp9Iy0DxUIxtydendkXlRRQJi58711gaE7KwskIwVsZJBreWcncwOgJyG
         vTbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mirWSre2;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id b7-20020a05651c0b0700b00298a76ba024si1265227ljr.3.2023.03.27.09.30.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Mar 2023 09:30:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 17542B816DD;
	Mon, 27 Mar 2023 16:30:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7CE90C4339B;
	Mon, 27 Mar 2023 16:30:01 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: glider@google.com,
	akpm@linux-foundation.org,
	robin.murphy@arm.com,
	james.morse@arm.com,
	elver@google.com,
	jianyong.wu@arm.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	Zhenhua Huang <quic_zhenhuah@quicinc.com>,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	quic_guptap@quicinc.com,
	quic_pkondeti@quicinc.com,
	quic_tingweiz@quicinc.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH v12] mm,kfence: decouple kfence from page granularity mapping judgement
Date: Mon, 27 Mar 2023 17:29:53 +0100
Message-Id: <167993012079.2285233.18016244231691896258.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <1679066974-690-1-git-send-email-quic_zhenhuah@quicinc.com>
References: <1679066974-690-1-git-send-email-quic_zhenhuah@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mirWSre2;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, 17 Mar 2023 23:29:34 +0800, Zhenhua Huang wrote:
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
> 
> [...]

Applied to arm64 (for-next/mm), thanks!

[1/1] mm,kfence: decouple kfence from page granularity mapping judgement
      https://git.kernel.org/arm64/c/bfa7965b33ab

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167993012079.2285233.18016244231691896258.b4-ty%40kernel.org.
