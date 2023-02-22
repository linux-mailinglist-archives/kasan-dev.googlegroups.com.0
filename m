Return-Path: <kasan-dev+bncBDDL3KWR4EBRBB4O3GPQMGQEKNVLF6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B40169F947
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 17:47:04 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id m28-20020a05600c3b1c00b003e7d4662b83sf2464336wms.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 08:47:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677084424; cv=pass;
        d=google.com; s=arc-20160816;
        b=YE/6J9baz4trxaV8qpWSPxPU4dTuF9tzK5LxFR5wQaLHiyLwGApS3PWHiWcPFBmvMF
         AfQy9DACXjkduIbtkTEMKkPsAaxm2rpJV8gme4U22FexHtMtHv4T23z3jjjmzom+Iplo
         Ag4H94txapxFOaiPFD819PdDKvobto/Ocs5UjPaPblNKCHWAfYpCbu9GbwE9e91GNptq
         iFbSTHC7/KfPxGfB0i8qFJQRaONKu4m+OYeUVLy4iOKhg9rOpRcqKzvle48M1ksmDpxY
         kQGlleF3JuCCoOBxXBVMHW9andf5Ego8rocdTmzbb9YLWRfb9CXaldHAZL7ekjl42Y/e
         IdXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YQsbNTM3P2UC6cxv5+g3HHlWXzuePIZRh1ibkE71znc=;
        b=hdXmJ1eUOy9cclcoGpr5W1XrXSOBxZS6IabfAdR0IdrQ1KgXTeuDzSvlUCTiNOIgiZ
         tqe3ah/hJCM43ScG9i+R+hihBKCMKlDFyIOMUhhqDoXey0DkvKVDK9D5xpoFGOCqETxN
         juVfsdaFi5b9Am/EJT3sGXdPX/woSFImsTKh8J1bTGP6rKEpK6q34F6l3jjo415vqn6C
         nG8ZJr0qddhppB59wKe6+L17PqCL41w8nW1Nsdk3atf9ZKGfcPL7n1C2i+wEZgERuAJX
         431AWSNkUaNRexXO6PdVXk3XTTZEF+R3Tc8KqdNe9IX+UE0W4jg+XhornCnmzLQb8x4q
         Vy7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YQsbNTM3P2UC6cxv5+g3HHlWXzuePIZRh1ibkE71znc=;
        b=pyO+YvlMAeU7jAxNd2PT7VJbSrjrcsYRJDt7j9PVaOQ3MD6UFx1Yq4r49PdKyZguPZ
         W/NS4LHJi8B8uzfkKaluidQ0bdE3Qv5I97UaTsvbgFBjnF3JNYAgLs6D8rkO2JjbBnBz
         vMvow5lix6oUV63U/of4B7/zgOkod5ykeobfuLZ67X8/ZqFdllgX3VSiPJSFfO5XMlaM
         U08LCtOe6OjIS6o4DrDZfuhm8RrUwqHUt9grbXb94xFeQk/yYoYCgz9/9FJyt2TpBjNl
         VHXhXiBlwBBWu/lJW7BP6b9yfRDTPoDffBw3F+hsba5cOCuXq3UUrjFVgno/2LOb490+
         BTxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YQsbNTM3P2UC6cxv5+g3HHlWXzuePIZRh1ibkE71znc=;
        b=nH2Roc93Xaqc99FK+3NcQuVTIwk3YvbJgg42UM8DfvmRgB/ySEflnlve7ZPGQpk7iI
         C0SaQUOLAdI/bwGTWgjrwyJiMrPHoYxAv0/iZqLUTxaiioaszDesmcixTyO+zmG0QP74
         9wfxvJL+Eu0ucNe7cAmjIkZYG0ej0LaRCmCv7DtQifsYmKfWKJg11E4wX87ijtPk9phd
         VNa4IBoMKYIPBqNxjGqzRRnHpHRImegY8u37dTVxdEomDkJc1G4nHIYqeNvDnUluo0IB
         PbCnN2rE6929WOT6ZLBU0AT3/nJAdeJtK+KchLiHQnKHjhnyuf/2oi2MVS5TuH5B5J4t
         h7DA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUV/QcrTA6vfP2BVNE8YOwB5Mj5zppEkMWgzqeqMQyjbzkrE1/K
	3ug05qQCHpgGqICW5doawO8=
X-Google-Smtp-Source: AK7set/s2ld2kc5J/PxcZiM4EblgvAIyZTbls3QpRQdv7kLIofXDZ2EQMJen5Q08wAlH9A8xm+4kQg==
X-Received: by 2002:a5d:638b:0:b0:2c5:94ca:d1a9 with SMTP id p11-20020a5d638b000000b002c594cad1a9mr188520wru.37.1677084423835;
        Wed, 22 Feb 2023 08:47:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5110:b0:3e2:1c34:a7c8 with SMTP id
 o16-20020a05600c511000b003e21c34a7c8ls839270wms.1.-pod-canary-gmail; Wed, 22
 Feb 2023 08:47:02 -0800 (PST)
X-Received: by 2002:a05:600c:43c8:b0:3e2:1d1e:78d0 with SMTP id f8-20020a05600c43c800b003e21d1e78d0mr3408501wmn.22.1677084422264;
        Wed, 22 Feb 2023 08:47:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677084422; cv=none;
        d=google.com; s=arc-20160816;
        b=jyCBuYLVpoNLTtgxop8VnUuK8DOqjH3RiuGkla0PYw/m3iCnSw9eCvMfL4spXVH3+Y
         ONoAWP/JfRbESOVzijRFYYw5adzlzBFBgdnlMv3HUDN+X43Sr0VROMMJNtYLdkVgpNRw
         +oI6ePUF5sA16i7O4BRHWru+Ko9KhfnV1m8aDRzaiVyDky1szZWJcoQJWJZlNidwHRWm
         nNiEUm1USLMBdJoRPX8febaxx/izv2WzvqFo0EjBRTIOxGNAfUId7W1mEjMkRqmY13sP
         vzMo29adwFYMHIPq/bSgeZOgo0YaZFozX5WdxM8ks/MMb0BphiVftWvoDeDRHRrqchy7
         BDWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RhddBEG2HCFT7evRzSBGb54ZBPFQx2fl3AMk8S3JmZ4=;
        b=w2QQkAjzQytQbXXvHeVv4s75Zo0kcbR7BSDBuYL18f7/l5ADe4srdn+x4MaGzgGzA7
         qLPRCLLQ3QBA2PgFAxefincPIVSigxU3nSVK9v4cl6mFdPehv6iXTmHnerS/9HyQzSp5
         Aph5EEywzBXGEJS5CYFm3MMMFe3nUi/fN5F96wGZMpqTG/41sJ7sS8uBMMqdQKNHyy5R
         ft4IOrogtrCh7F5R1Tn1Q62J/V2xQ/2ZZeAFsqxVmAwrhLWua6fNpbMxQltjixoVF64N
         3A7P72VapEUQZY2L+XJIum8CiTG7biXCY0ue25t+y+w5piCZRgcboC3iDUVRolMJu5YQ
         oSnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id az17-20020a05600c601100b003dd1c15e7ffsi305811wmb.2.2023.02.22.08.47.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Feb 2023 08:47:02 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 05F07B811EA;
	Wed, 22 Feb 2023 16:47:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4E5E5C433D2;
	Wed, 22 Feb 2023 16:46:58 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: andreyknvl@gmail.com,
	Peter Collingbourne <pcc@google.com>
Cc: Will Deacon <will@kernel.org>,
	Qun-wei Lin <Qun-wei.Lin@mediatek.com>,
	Guangye Yang <guangye.yang@mediatek.com>,
	linux-mm@kvack.org,
	Chinwen Chang <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com,
	ryabinin.a.a@gmail.com,
	linux-arm-kernel@lists.infradead.org,
	vincenzo.frascino@arm.com,
	eugenis@google.com,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH v2] arm64: Reset KASAN tag in copy_highpage with HW tags only
Date: Wed, 22 Feb 2023 16:46:56 +0000
Message-Id: <167708438950.477413.8786796815107449095.b4-ty@arm.com>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230215050911.1433132-1-pcc@google.com>
References: <20230215050911.1433132-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, 14 Feb 2023 21:09:11 -0800, Peter Collingbourne wrote:
> During page migration, the copy_highpage function is used to copy the
> page data to the target page. If the source page is a userspace page
> with MTE tags, the KASAN tag of the target page must have the match-all
> tag in order to avoid tag check faults during subsequent accesses to the
> page by the kernel. However, the target page may have been allocated in
> a number of ways, some of which will use the KASAN allocator and will
> therefore end up setting the KASAN tag to a non-match-all tag. Therefore,
> update the target page's KASAN tag to match the source page.
> 
> [...]

Applied to arm64 (for-next/core), thanks!

[1/1] arm64: Reset KASAN tag in copy_highpage with HW tags only
      https://git.kernel.org/arm64/c/e74a68468062

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167708438950.477413.8786796815107449095.b4-ty%40arm.com.
