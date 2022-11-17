Return-Path: <kasan-dev+bncBD22BAF5REGBBRET3ONQMGQEO43YQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC4E062E9E5
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:54:45 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id i133-20020a1c3b8b000000b003cffc0a69afsf1132015wma.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:54:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668729285; cv=pass;
        d=google.com; s=arc-20160816;
        b=y7hOrgL34J1Z07G/SvheIJOMdpIIuVgiHshEqbaI43OGNuDABHZkvN8DDNLDFz17+F
         a7S9MjDJYK1KGwOvltFEIs+6IVgvWPuLDyESF3uXnRA27K7Sp+pzpLwsCzXTMtDiqFpl
         vzUGTYGtGSKD6sgxGia9Q8FRjVRBSnla/OP0t5/5ibMjGKjUFIs+X0QKyY2tz9GX9jYT
         qOIQx2aPs4F1S6NcrSUvpJ6O+2Ju9fc1zUS4zEvKIV6ZIag+gXGdyQsG0rtbStcJGbX/
         wKeR1wjpoXvssLTABkSqPvfWcZsXStZOLmZDO9nCbR63e2BUQFxvCJ7dn7KmOhnd5jgO
         ffrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=dSGXoBh/TvAsGG1MTd9GzkUqr2qRz/sX+xt5zraRhXA=;
        b=gSLDOsK6c1T8gCovfrcDGZcl1eSR0Qac3nUMB7Z2oXeg4HXN020ualdmwqtWoJpSCF
         SEe2w14q9YP8/hMmNpspcsHATrw1C3CnTDel95xPcyu5qR7XSd7cMiFpOXWDYTOsyxvl
         cN56eMKJHbci/Ho/BXWQ38hL92roRozRah7WXhSREBvcf5KKuvnLyfdOgndNnEa3lwE4
         tO4KHMylOlqqFdbNbrTVVDKcX0+j3CaEv0jme9TM+TzokTvD9LCdFs9vaFDQ0/bakh90
         UeLFq7BPMoNSPBUMTRP7Z2PXTAkQ6zs/pBn0FWkhyy7RAZF5ksJfVgl+0FUGeHjrSVP6
         rMiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=joaplMC7;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dSGXoBh/TvAsGG1MTd9GzkUqr2qRz/sX+xt5zraRhXA=;
        b=o11BOKMfTslGrRBOjX00QD74SwouhKxF58aCNAgRw3P/2wovZB7K985hhUoN8bmgCr
         O+AgG/SyalfENuplIqfZI3+gROMJqfyDQzg0F2HNGzml+FiG8kjLggpIAkkbThjOf/V2
         4VkFUqV+lLP4kLFa+mQBM5TqkbmtSOFBdRUvbzCPYzZSMp0UjINP2piYRrW7gl7w70sJ
         amdEjpw/EhMdk4SGk/RRb6/q1Y7PjAj72dyAs9TPaRc4mop3COws9NqlY+qTh4X605fx
         rQRiTkK5sE9dH6ATiiICuyM0TLzMm09Hj5sBWudqtTtdj/49Ra1ZVUAZSJhLoBr47PMr
         bWvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dSGXoBh/TvAsGG1MTd9GzkUqr2qRz/sX+xt5zraRhXA=;
        b=215lfsiatmwYmo2G4S14+nnkN3gPcfNq4U9HBGLclrb2THGAMF00EFczeXm5p5Al+J
         F9NrIv87jnkL54iwgJRjYhGA8ll3FvzK8cuLOl6HKGugBYqMO20nvOLdcpDV7njo5xJg
         5Eu1liBcuu/lQGJA7XTIIINGC0U4uWL0SJp0i/d4ZpHLQcGXmG5glii28n3ANNegerV5
         NRsndkYWEUfxknWFzFPSQPrq2xpFUAlOzH7iEhdcns0GHblw9mMu17WpS6asu08sbw8w
         59EQxq5aan++2hOWDTqCMAfrwnc9M8FMcTI1vL3kkKTLhLamD4XzL26PCH5WvcnYaJSd
         vHlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnPpy5E54gKLuD/xOwJQsUXB5uClEJAwH2LWGiNMZiBO8qnJSZw
	FbTop4i6PUokkNdyPKxyhWI=
X-Google-Smtp-Source: AA0mqf5YFSCZcFmAPiBG538ecvFNUByZLTawrD5mDoDXXd6UUE+hiJi9PIa+lWlK5FsX1Q+jnm83iA==
X-Received: by 2002:a5d:6803:0:b0:241:baae:6a6c with SMTP id w3-20020a5d6803000000b00241baae6a6cmr2256538wru.716.1668729285168;
        Thu, 17 Nov 2022 15:54:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:602a:b0:3cf:9be3:73dd with SMTP id
 az42-20020a05600c602a00b003cf9be373ddls3273788wmb.3.-pod-canary-gmail; Thu,
 17 Nov 2022 15:54:44 -0800 (PST)
X-Received: by 2002:a05:600c:35cb:b0:3cf:781a:4310 with SMTP id r11-20020a05600c35cb00b003cf781a4310mr3275232wmq.150.1668729284017;
        Thu, 17 Nov 2022 15:54:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668729284; cv=none;
        d=google.com; s=arc-20160816;
        b=P2dnWjmDL8WdVPKDQJn0Rt20wRU12e+yeAammdfSFEm4yNYym4+QiCBzSTfDVdi9On
         WKKEnthcO/e/iXS/BByZ5P5hiRC7yeBg/p3Kfp3UkgoAPLBKpSlk8gQB834o2dDzO0gt
         wAqw8Orf6BB+0IuYks0fbEi0TXbz7JsdYWdmGMkvSkYA/sIOIXpy7nla99BflJY5MUPG
         kAtexpmtRYViARbGKIA6YofbScgY2M3/DoB1CztvNjx/RIAROwXwA2hAPq7gSwO2U8fw
         0rS/QybJhdX/6kOi79SOpkFz13iKRKfHPhqy/QloFJdpQh1mGCQuikKpvmUhz1jCQ5kG
         P3KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=RFpg6k3CS9ptcsmhZskMonyASz1XCiVRhTPfTUysBrs=;
        b=zFJpNklja4OyYkGIEsDGRidEgBBvikZ3Aw97KNwMuOQrRyiXi0i2yP8KSZEkbuvn68
         jwGRu6FVWf3FwvvVymRl04/JGIo6UAHzM/qsNokmcf1A5H4irByabte1MOg5MnQ9jJl7
         2tdRoICdN2hq+7Vn0NZqBe8kFDD/Zc+kHdgD6FMMwumfwYwKVNqDBF77mg9i5UlthE4i
         1CtvuSQdhnuiXGAy753jz7KZqZldVcqh4qku+r+hfT/+Cy0z2DIfql+cva15iE2/mgNW
         2s8SXdzxJWv8jooq0BFSCoPz0iBYpU4k0VxVIy8VTc5vHyWRT60xeZTBm8PJCcOVJSL4
         ckkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=joaplMC7;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.24 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id 124-20020a1c1982000000b003cfc33e8333si290385wmz.4.2022.11.17.15.54.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:54:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6500,9779,10534"; a="314159185"
X-IronPort-AV: E=Sophos;i="5.96,172,1665471600"; 
   d="scan'208";a="314159185"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Nov 2022 15:54:24 -0800
X-IronPort-AV: E=McAfee;i="6500,9779,10534"; a="703530903"
X-IronPort-AV: E=Sophos;i="5.96,172,1665471600"; 
   d="scan'208";a="703530903"
Received: from vrgatne-mobl4.amr.corp.intel.com (HELO [10.209.115.197]) ([10.209.115.197])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Nov 2022 15:54:22 -0800
Content-Type: multipart/mixed; boundary="------------Lh9aXApYj7BdK6v1bd25dwlY"
Message-ID: <41ac24c4-6c95-d946-2679-c1be2cb20536@intel.com>
Date: Thu, 17 Nov 2022 15:54:21 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46
 kfence_protect
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>,
 Peter Zijlstra <peterz@infradead.org>, kasan-dev
 <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>,
 open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>,
 regressions@lists.linux.dev, lkft-triage@lists.linaro.org,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>
References: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
 <Y3Y+DQsWa79bNuKj@elver.google.com>
 <4208866d-338f-4781-7ff9-023f016c5b07@intel.com>
 <Y3bCV6VckVUEF7Pq@elver.google.com>
From: Dave Hansen <dave.hansen@intel.com>
In-Reply-To: <Y3bCV6VckVUEF7Pq@elver.google.com>
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=joaplMC7;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.24 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

This is a multi-part message in MIME format.
--------------Lh9aXApYj7BdK6v1bd25dwlY
Content-Type: text/plain; charset="UTF-8"

On 11/17/22 15:23, Marco Elver wrote:
> Yes - it's the 'level != PG_LEVEL_4K'.

That plus the bisect made it pretty easy to find, thanks for the effort!

Could you double-check that the attached patch fixes it?  It seemed to
for me.

The issue was that the new "No changes, easy!" check in the suspect
commit didn't check the cpa->force_split option.  It didn't split down
to 4k and then all hell broke loose.

Oh, and I totally misread the kfence ability to tolerate partial TLB
flushes.  Sorry for the noise there!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41ac24c4-6c95-d946-2679-c1be2cb20536%40intel.com.

--------------Lh9aXApYj7BdK6v1bd25dwlY
Content-Type: text/x-patch; charset=UTF-8; name="kfence.patch"
Content-Disposition: attachment; filename="kfence.patch"
Content-Transfer-Encoding: base64

ZGlmZiAtLWdpdCBhL2FyY2gveDg2L21tL3BhdC9zZXRfbWVtb3J5LmMgYi9hcmNoL3g4Ni9t
bS9wYXQvc2V0X21lbW9yeS5jCmluZGV4IDIyMDM2MWNlYjk5Ny4uOWI0ZTJhZDk1N2Y2IDEw
MDY0NAotLS0gYS9hcmNoL3g4Ni9tbS9wYXQvc2V0X21lbW9yeS5jCisrKyBiL2FyY2gveDg2
L21tL3BhdC9zZXRfbWVtb3J5LmMKQEAgLTE3MjcsNyArMTcyNyw4IEBAIHN0YXRpYyBpbnQg
X19jaGFuZ2VfcGFnZV9hdHRyX3NldF9jbHIoc3RydWN0IGNwYV9kYXRhICpjcGEsIGludCBw
cmltYXJ5KQogCS8qCiAJICogTm8gY2hhbmdlcywgZWFzeSEKIAkgKi8KLQlpZiAoIShwZ3By
b3RfdmFsKGNwYS0+bWFza19zZXQpIHwgcGdwcm90X3ZhbChjcGEtPm1hc2tfY2xyKSkpCisJ
aWYgKCEocGdwcm90X3ZhbChjcGEtPm1hc2tfc2V0KSB8IHBncHJvdF92YWwoY3BhLT5tYXNr
X2NscikpCisJICAgICYmICFjcGEtPmZvcmNlX3NwbGl0KQogCQlyZXR1cm4gcmV0OwogCiAJ
d2hpbGUgKHJlbXBhZ2VzKSB7Cg==

--------------Lh9aXApYj7BdK6v1bd25dwlY--
