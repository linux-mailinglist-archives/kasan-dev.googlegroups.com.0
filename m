Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5VWWGFAMGQEX5MJTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B3E3415C38
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 12:48:23 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id q15-20020a67e9cf000000b002d714e1c0d0sf2359698vso.16
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 03:48:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632394102; cv=pass;
        d=google.com; s=arc-20160816;
        b=IttQdjpZekGrjR2CJ1syeg0c4KlEA2FikgR1Msh4MFSan6kqQxkTZ8ZsMpSPhDCOFn
         tglyGTPH8vl/riVITLAkk0vlUVho9Yas9S0zs2T32xCJW0CZzo4I2UF4t1+KWOTQYhMj
         ZwdQGj4hrJylcjdb8id8eT7sIqdlMF1sUtZGP8l6on72KRcISvs1C+IFBRDCVh38b45L
         +nXvr3VM8ofW6eAZ8YbBm+W5pJUEclvfe2Z0WSJWADflr716NUpOFhKcMI41Ki5G1GBB
         sIE+Ues927jTgl3nSpn+3GyumLJMMv17W9I3X4kI6RMsIik7CYbPt5akmZpPBD9EOz5o
         Sy5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=k4e+FxZC+h8HtvtrNxNsX4mn1mAK0653HPw84pStoO0=;
        b=Qj1ruYviWxg8qBuEu3ZAHCxip90EqOKFl+8chC7f4v5qbILxrxzw9qM3jyNBkG6/M9
         ksimRnINN2HRzXnpek/yJ4IBjjqPNIqwPTAF3U8nfMSP2Pqb0x8wxwdOSw6x5tilFAAs
         gwvj8PWgleRvt8iWmvpmn3vSQ/Dxv7tWVqPEnBEcLzpMhDnCzex6djIO0SYi8PS+oYGU
         BpuNL+yd/dclTVlHYgtAVbSQx5hRsvtXOC1U26FN8OvqLV/Tu3li1tTOpDjd+uLj5pw7
         nbd8X//mOeSVBLwmZuxf3rywa62Wu4geSrNHiltTY4oqVN3GBCjw3hDuI7X5yJblPoa+
         OdPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lz2zeNS9;
       spf=pass (google.com: domain of 3dvtmyqukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3dVtMYQUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k4e+FxZC+h8HtvtrNxNsX4mn1mAK0653HPw84pStoO0=;
        b=WMytKpGHCpIzNDJsFIJMvHspDcJY6nBGO4nq0TXQr6JfpmAYyfHpSqUt0/gLZirPmP
         7J/toSjs9TYw6ewh2WfFMuA28RfWkwQ9rvtLEL5pRiuwdDdizzGA7Snhsvm5lpBoSmEq
         EbDFkXIR9YyPHV9g5YaBSBdEPiBQkO8If3x63h0qc/YIEt8DIM7UJ/wwgErS59yVWwtd
         lDHIJsHHGi6ApYdQ9wOXzi4rXbPUG+07JX5PEmPs8xs5sZ6puzXjtI3ADR5RGQbxlYf3
         /sG57R69IWyp+5qcsKkeLdU8XXYILlZpWGcKcPLLiduy6d7QeoNtm37hbq9JIO4OQrDw
         AqBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k4e+FxZC+h8HtvtrNxNsX4mn1mAK0653HPw84pStoO0=;
        b=rdXHlDk10TlwcZDH7XKBKRJt/5bHmjdlTqsg6GSb/wM8kBVd4vzhqlFPdN5rGIxXSj
         w2zzKDjoWM2RUJomNQe0BlqUdlNJWhqFzAOx0CC5/PRua5XhQmqzUpe08/kzqxaTAG/K
         2ezGRvFuwGP0/We664HG5aXgROQt49WtydLcRVEd44keJmmOtkQNCjPC0elapdffxsf/
         BVKTj8qQtvR8Wr6wNpAemVMRTs5U63iTSTu03fdk01LX9CX5jkDYr21ynwtCsqz1pwCJ
         DabguU7dGoCs8BlfH9yZq8krZi3r0v9quXCZAFrcJFx0mZw3emFfFqfYzk3oYmHS6yxq
         n5DA==
X-Gm-Message-State: AOAM5303ATyWPfd6i0giz51rvP+V+FLa5dr7jZTUgAi/xIs4Oh6yrDYJ
	CP7+3cyricBIqnhT+IyfrUc=
X-Google-Smtp-Source: ABdhPJyuJ2mCfP1KPdrk/9UXREdVuUeTurs1RaG5Xn9z54/2i/kZKd+VDP6Er6Q0mkOtIrHYjIb2/w==
X-Received: by 2002:a05:6122:1ca:: with SMTP id h10mr2800092vko.20.1632394102651;
        Thu, 23 Sep 2021 03:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:1144:: with SMTP id j4ls1209510vsg.3.gmail; Thu, 23
 Sep 2021 03:48:22 -0700 (PDT)
X-Received: by 2002:a67:2d92:: with SMTP id t140mr3028603vst.29.1632394101306;
        Thu, 23 Sep 2021 03:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632394101; cv=none;
        d=google.com; s=arc-20160816;
        b=Zt2Zudm8Fo96VhdEwBEFCw52vr9iT9gg0idPGoWrawBz+fglb0A5YRFAoqQoWyM/Og
         POWy4u2I224IRhJSTX6nPuvuVmXPWqO0vxJ8w/0aA0Ibggyxrz/J2Mgz5ROXerhlmR/R
         tPX3RZr5r80nABgoEhOQx7zHMWx5VvZb+nS9/78DUnW4LWPUCQPruQYIAFy5eJNMgVjd
         dEJBcOrF1ZDM640C3yoNx+9+KA05CoGdng0tepFxjbt6NmFPkJSBNTjk9z4+QjSkow03
         7G6QXY33hDc04NWkSdGukffcMgM8lP6vVX210se4Upx84pxt4iF5bseMKr5LAM398f2j
         a87A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sS022PP0nBNSy8OKBYkYKJTWDCY37FWogqIg9gOqwaw=;
        b=yzC3De0Ci/4u5AecHx9j4nDCrS6Y0KGFQ5lU8OrmZCc4ttbbei8fBJykO0nZxAjO97
         o0rTjfyPsMjnz1O02eyaYAKSAVSoKLsEunLM3Io682JZVS0evm8Y3C0XLUk2pv3bNHbp
         ySilzTZhemfrIHzCFXGqzgntrB0FplLYf7LxH18YGzDWUY1FM8gUGm4MDsXU0/GVlFxO
         vQBmKwXkAsr+0KmPXW2b2HxhptIzsNNMSP/TF12L1mBhyteHfdRufvSVMc5ey0AzUTrd
         3yLFu41V60bu0/AI2PQVltgD9UhYx+9ohRzWP/6fp3HjKfvFqP4E0RnkPIiExZq3y/nk
         6GEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lz2zeNS9;
       spf=pass (google.com: domain of 3dvtmyqukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3dVtMYQUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id u64si276565vku.4.2021.09.23.03.48.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 03:48:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dvtmyqukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id b20-20020ac87fd4000000b002a69ee90efbso16525356qtk.11
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 03:48:21 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:bd72:fd35:a085:c2e3])
 (user=elver job=sendgmr) by 2002:ad4:4990:: with SMTP id t16mr3775079qvx.32.1632394101026;
 Thu, 23 Sep 2021 03:48:21 -0700 (PDT)
Date: Thu, 23 Sep 2021 12:48:03 +0200
In-Reply-To: <20210923104803.2620285-1-elver@google.com>
Message-Id: <20210923104803.2620285-5-elver@google.com>
Mime-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v3 5/5] kfence: add note to documentation about skipping
 covered allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lz2zeNS9;       spf=pass
 (google.com: domain of 3dvtmyqukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3dVtMYQUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Add a note briefly mentioning the new policy about "skipping currently
covered allocations if pool close to full." Since this has a notable
impact on KFENCE's bug-detection ability on systems with large uptimes,
it is worth pointing out the feature.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Rewrite.
---
 Documentation/dev-tools/kfence.rst | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 0fbe3308bf37..d45f952986ae 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -269,6 +269,17 @@ tail of KFENCE's freelist, so that the least recently freed objects are reused
 first, and the chances of detecting use-after-frees of recently freed objects
 is increased.
 
+If pool utilization reaches 75% (default) or above, to reduce the risk of the
+pool eventually being fully occupied by allocated objects yet ensure diverse
+coverage of allocations, KFENCE limits currently covered allocations of the
+same source from further filling up the pool. The "source" of an allocation is
+based on its partial allocation stack trace. A side-effect is that this also
+limits frequent long-lived allocations (e.g. pagecache) of the same source
+filling up the pool permanently, which is the most common risk for the pool
+becoming full and the sampled allocation rate dropping to zero. The threshold
+at which to start limiting currently covered allocations can be configured via
+the boot parameter ``kfence.skip_covered_thresh`` (pool usage%).
+
 Interface
 ---------
 
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923104803.2620285-5-elver%40google.com.
