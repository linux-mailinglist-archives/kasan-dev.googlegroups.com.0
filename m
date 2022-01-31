Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXW32HQMGQELKYLJAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5794A404C
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 11:34:23 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id c31-20020a2ebf1f000000b0022d87a28911sf4431179ljr.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 02:34:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643625262; cv=pass;
        d=google.com; s=arc-20160816;
        b=RGnqQFo6I0VvEFmMipDssbk5uWnjpLAe/jsz+mJYSp2Tb7bFv8px1CHrpIiUox6+QD
         GkgEoLeRr8+U37FJ3p0zhbBtSktAMmyI9fVxrJeljp+E/0O5Ct4AHJBYBlxMyStytm3a
         fWNsPU3nOTHXGIQYaLhFpVj7mCB9kgoZqkFTOt+PbK7CbvyxzyWhT5qDJHvlitat54Y/
         EE23l+rx9WwjsYR994WgoRfH/Fr2PEPXLTgh48NT8oSWX3EaVQoKMnV5eYEXpaH6Hj/r
         hZFclVU2V0SSU0VPBAzPJDgP6T7ytWBAyo6q1S3wblZsZPAFtAxnZFTXGjSGXr65lQ0/
         NgfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=pDKVoA0jW/4qcJW+N4mdYzR250npixTH5gRJV8MjD4E=;
        b=ID5Dg+GKqnxD8uF6J1sRmtFfx/0cL/YPUmbUDGaVzizrZlkG0C7NsPzLm8dLeduPto
         +YAcSRPY7KfO3i0EdV8Jls5t9yE/+AwfVG66tlp1u/CUuZoZxGDkBcBfITJ00e3i3TY4
         x7cEL+u9MXY/G9LuZPx40aUF8AR+ine0d1k7Aj+3rLyF8qECjb5rVHPR0cw6xByErIkH
         NYr80y3s5NkDVTtRkAVxTf14drnALDfu4OfwXmNuWQiEX7rY2k8hQFy94ZHHNjH1dleI
         9WnnlXWr/r1+kFehth0q6HgTugPFt2BG9dkJVlvqQVHeZ7iAbcWIvUWIKilR1f7j8bMX
         KOXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HaftrDy8;
       spf=pass (google.com: domain of 3llv3yqukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LLv3YQUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pDKVoA0jW/4qcJW+N4mdYzR250npixTH5gRJV8MjD4E=;
        b=ZqIpow5Yd2UEPx1vjjTvGCvxo/PyE5aylON9qmqgqAQ3AwSrutD67vPVvAFfKNSY+x
         uGpG7C3UXoO3nNtLDopk8Unk1XMrbsyZHWFDEJYPqz0B/tJ6wDdYiVoWJNmLYGym7LBY
         10CqVms3Gd/ggvyTM2XGEeM8bD66Gor392wDjl/K9N/OrLYbM8PmDK2qudARctcClREu
         nLn5Md0oOGQ58zRY4/okpgGi2jXOqCffJWDUBFU3F2YLueQsOsG1X88CK+aDDjJ82agk
         LqznAV/JBHlXV9vK8b7jjnpA0rbaA/JSqxawkNj+Blg/KsvAkkH6LcHUtbrY7xdyZn+o
         O6Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pDKVoA0jW/4qcJW+N4mdYzR250npixTH5gRJV8MjD4E=;
        b=C+5rB8mWo9AIzu8QzH7kH7Gf2mfdCLHxu3uWYo48eAFRR7qiM0gbb6NWED2PY+19dc
         69lUuro29WQvaeKEa5x/F5PKY3OPtdz3If6XYlimSuqsK79HpPZHViKslpjPDbIDYCDi
         xnajHT8VeGxA2Wvwm9rntueRl9Sdb3TkeGffERPiwNtJKgfsoVhW6adkeUdmI81ZpglF
         sgK4zV27V9zPvt8affmwn+/4DhsZZCuiy0Lu0gF9uO6Wi3HLWIXUomZWz3nu97rqAyiF
         fHHJjFm56hBQgWI2umOhMWr97GHIX5R0UOAwhjpboaiUo1RZIdpWNKz9vxBY4VRhbCtl
         H1Pg==
X-Gm-Message-State: AOAM5323aufLKcghfArx6MWRw2gUPrpCqPoFGOGaZn3mmd5hz7v1w7/J
	+ZcJuMf6vsiXDzZI6VV2G5w=
X-Google-Smtp-Source: ABdhPJzv7jzRaY1MXCbam6MSp3Llf+mNiE+Tm2FdSLubS7RZeQ3A2+DBZ+qkNJ7qTZsMrbJ+Fy4Mhw==
X-Received: by 2002:a05:6512:22c2:: with SMTP id g2mr14423854lfu.638.1643625262471;
        Mon, 31 Jan 2022 02:34:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:198d:: with SMTP id bx13ls2582203ljb.2.gmail; Mon,
 31 Jan 2022 02:34:21 -0800 (PST)
X-Received: by 2002:a2e:3c03:: with SMTP id j3mr13359219lja.294.1643625261171;
        Mon, 31 Jan 2022 02:34:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643625261; cv=none;
        d=google.com; s=arc-20160816;
        b=zi1ANSz3aKh8+DWcgnzc+9y93xUOUBNxdGc4VvkE2NZsMB7ud02Fa63wQSAuZ8t3D2
         FOTahm387z1viqKqpqxlw04/KU+5/DFH/iZAmQ4NvvhOWaU5+oOK4b91RWPwANyN8OuW
         azfOBR4PswuISv7MoZBBm2oKiWJms0hwKsxMiAmiZnLYslWKiGI/uORW+pe/uR5JQNZB
         uO3HAMt1pm7XlrfABARuNLggfgFhFFA1HW72kRxWlzAqkYicPAymYOTaEHIQe0hxK0mi
         315bhb5M3skLTxePsyg8rWrtxuyVMbYPfURrk776LvBCAiAlROiIkrud8KgPeJVtpaZD
         SuPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/V9lGjda+sqhZSBIJFUSQvnNkRukniydQDjwMIcq1AU=;
        b=OYfc66qWeDvZ+aM3QErGigWnZwXWstlWI92pMNkmt4vJvHw+XB0gAFvbOvWg3xXU+8
         PEXKHk7JttKR35wYKgczb67rlqw6Q+MMsx70s3kAhmks4DbAErnQiCn6Cl8cLoRX95RT
         k6J3Hjc/Fk3SvsOacjrFI3/EkUd8vN3WJ9vTwhiCFCk2yKYDZAN9V8EN1MB54Kxh9sd1
         0512GsmW7PC+nHFc/IsILaAngLgDt3JeD11mmYWJqhHfgWy2zWDnQsuQrOnKhFdZwfGZ
         SklSAWudev1xGRinwyAq9TLI7r5Qoi6SSeuyKu95W5MD76MyVLOrvczT16VAHQog/+xN
         +eEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HaftrDy8;
       spf=pass (google.com: domain of 3llv3yqukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LLv3YQUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id l5si514511lfk.11.2022.01.31.02.34.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 02:34:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3llv3yqukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id q3-20020a17090676c300b006a9453c33b0so4767860ejn.13
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 02:34:21 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:76:dcf3:95f9:db8b])
 (user=elver job=sendgmr) by 2002:a17:907:d28:: with SMTP id
 gn40mr12058531ejc.750.1643625260505; Mon, 31 Jan 2022 02:34:20 -0800 (PST)
Date: Mon, 31 Jan 2022 11:34:07 +0100
In-Reply-To: <20220131103407.1971678-1-elver@google.com>
Message-Id: <20220131103407.1971678-3-elver@google.com>
Mime-Version: 1.0
References: <20220131103407.1971678-1-elver@google.com>
X-Mailer: git-send-email 2.35.0.rc2.247.g8bbb082509-goog
Subject: [PATCH 3/3] perf: uapi: Document perf_event_attr::sig_data truncation
 on 32 bit architectures
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HaftrDy8;       spf=pass
 (google.com: domain of 3llv3yqukczc5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3LLv3YQUKCZc5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Due to the alignment requirements of siginfo_t, as described in
3ddb3fd8cdb0 ("signal, perf: Fix siginfo_t by avoiding u64 on 32-bit
architectures"), siginfo_t::si_perf_data is limited to an unsigned long.

However, perf_event_attr::sig_data is an u64, to avoid having to deal
with compat conversions. Due to being an u64, it may not immediately be
clear to users that sig_data is truncated on 32 bit architectures.

Add a comment to explicitly point this out, and hopefully help some
users save time by not having to deduce themselves what's happening.

Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/uapi/linux/perf_event.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 1b65042ab1db..82858b697c05 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -465,6 +465,8 @@ struct perf_event_attr {
 	/*
 	 * User provided data if sigtrap=1, passed back to user via
 	 * siginfo_t::si_perf_data, e.g. to permit user to identify the event.
+	 * Note, siginfo_t::si_perf_data is long-sized, and sig_data will be
+	 * truncated accordingly on 32 bit architectures.
 	 */
 	__u64	sig_data;
 };
-- 
2.35.0.rc2.247.g8bbb082509-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220131103407.1971678-3-elver%40google.com.
