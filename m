Return-Path: <kasan-dev+bncBC7OD3FKWUERBEUMXKMAMGQE25YXF4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id F068A5A6F99
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:11 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 92-20020a17090a09e500b001d917022847sf5187146pjo.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896210; cv=pass;
        d=google.com; s=arc-20160816;
        b=W/qEI0fEPISg7UDdjghtdepLsf/bdZQlKyGFoqp0B+/tEOIlc+rMcqwNSHEI57023b
         2zF4VLqgNPi/Y2katKTgebsubeurVHT319Dd3SFAqfZo7+nLkkLHjOsbpz7VZochLKkY
         /dmbGR8s7Z0u6vYmBcID4uMnMnWrsW6nImiPM6g3Ru6AyNFlaqUdAxKi1hRHde+qNHM3
         nRy34G8Hn1H78axHpzGepfTtyKBgm9ZlaZENQ2IKoR5DSzHdL5Yqo85ft6yipk3qVNyF
         Vqny2OCr0fOGAL2XGonXcLCgiZeARXYukugGN0K9CANR3tWEaHnzsLxcjVA9MB+bMUg9
         LBYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XCsHay8oxg/pe+CvgLGD7uVNP3tnZYW9BoAu4XjwJ4c=;
        b=HxkQnfjhhA0+HxKh3bScTtXtcTOAia2reJFwTarhPjSFm3q299i5oY7xgiS2ie9Fbq
         MKW9VeCmpLMBP1YRxGA7qQnPXP1kohupp8F+IDAWxNu+BIKCuwBEBQUKsVitxi1tXE71
         VpiG1GKDm5znntaAu29uWs/GW7HQPDDwUT0oDLYprS0bjvXmYfqfaZlIA1mObG+ogRhx
         pBjX2oYHyRyXa5HoB3bK115uLw7upE6I0d2pR5Y9yIjMx3bq2qCYMMSo7QoMwNaGIpkH
         NI6d8hT1Hq/2k+VhuxLO9jvTF3MdRrYskwuB0tIIZdpsYL7DJy9/d9DTrcotySnDZxyy
         c/8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hebs9Ab4;
       spf=pass (google.com: domain of 3eiyoywykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EIYOYwYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=XCsHay8oxg/pe+CvgLGD7uVNP3tnZYW9BoAu4XjwJ4c=;
        b=cG4pNddbrrwKyIBFLHlFmOhYQ57WO7FmTCOSn8XZO1+RhoWO3xjbWIA3CvTMAwuDfP
         7QB9aQaiKXFMpyv17Tr8UD0GjrhEg1kj1MNfl6yR1Dbw9+CH9XkGFa2jAIDYuS2EsNjq
         F68ySqWz3HsiD+oVWbBO/jJajmuPpM7RxQ63o55OwuY1kWl9bfs+N/XkEwOrq9WgO9bN
         /1kWSU36m0pSIEABwCilVnnAcOrr/chM0XX0MxMhH/kB72sOQOO2f858ZV0dTVYhesiM
         yToiITpi+dLa3QL0huwpmiXcFOmlfIix06hTHUOmgzfBywKoRdx80fb3I/USn8YYO9SJ
         D9Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=XCsHay8oxg/pe+CvgLGD7uVNP3tnZYW9BoAu4XjwJ4c=;
        b=ksFDHMlbyPxb3n6/k5ExcmmT4vrgMiqzWaHmtDni6hlAnhUMyhGmM+FVlzWPFj9qSX
         Zoxs+WbrQzC+ax9Nd0qozoesbncBP+yB9PGKc4IiEvxTGLS9WW+1svUTp1u2erfZGhoh
         ChSgS7D82aMhHwnsgexU3dbLnPhsEn2a3KTlX+CXMwKApRzEma66TyCps7XsdVWeC3NN
         mQ17SR0GKGdcLXfSHP4XhWrxVytutgQ+Oc2S0nP2ZoOcFfS1Kjl3F7bZAUejFxNUWnlN
         +Lx9K3DjtkWTDkZNoOPkmiQTiOB6XcRGEEiH8jVBAxGinqQcVuWKlf4PMOkVuiTpUDT+
         +3Ag==
X-Gm-Message-State: ACgBeo38d/kdKm5s6erfyNZfzGSTCrniSEuratfoNkoaehZhSEAZJhgM
	wSyZ1t4gxBkpG81iAgrf46M=
X-Google-Smtp-Source: AA6agR5S4c5BO/ulprVK3GH2Z90bm09uZashCWaNSIFivCETLyMwADONtW+POul1BOJ7inaNXqwILA==
X-Received: by 2002:a17:90a:aa08:b0:1fd:8016:29f1 with SMTP id k8-20020a17090aaa0800b001fd801629f1mr54439pjq.23.1661896210643;
        Tue, 30 Aug 2022 14:50:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:804a:0:b0:41d:9c6a:a064 with SMTP id j71-20020a63804a000000b0041d9c6aa064ls5441328pgd.3.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:10 -0700 (PDT)
X-Received: by 2002:a63:90c3:0:b0:42b:231b:7cbc with SMTP id a186-20020a6390c3000000b0042b231b7cbcmr19824201pge.115.1661896209941;
        Tue, 30 Aug 2022 14:50:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896209; cv=none;
        d=google.com; s=arc-20160816;
        b=dA6yDw/zYRpSfqnGhaWlCmTpagPZQFg/TXxAO0on0cusinmi5TK7lox7vRLYVnVjh7
         F0iET7QlzB/OMe5wUiVjNczTDPWIsf7S+3Ce5qtCZvkZrzjKPoFCKpbLT7arWOpdKC/E
         TdDgfOHM37IyA0zNaB6fT/kVLlU+Ud21ukOnNizXvPC0sGad8Z5h0NgJ7/GJwpXYp2uw
         QX3NjuEeSzIzsRTpvkHWs6GTHFwqzrxPwjT8hWUgetsoB9HooLKXWgGot6jngGHCt/iO
         DfiC74XwQS5x4bLvPrxgRaZhBChwz5TNdFdVpcy0OU9cc5gFRd6BHXbr36udDENqsu9b
         4zNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PaZc/ErQmIz9CmZWuOwZKmMvFAFDhrfR0u4+oqULyqs=;
        b=K/ZiXrhXG6q2vjZL6+xLvxI+dlbdkFlAZr2rKfcJjTsI1wTwrde0txLE4fxd+26asX
         ym99bL+sxqJw86geRBwMmUMImV7xBd1WbwkN6k0tDR/bQoW/JBo1+ALdkbv7THRV+r0g
         CyQP7RmLNvhoVuyHSKrvZYuFYHTSgFezQHGKrg+BWqfc6p+xugc9a6dCsCSKskUxaJbf
         Ont5gvyH4BSiyQVFX5CnKSvPzM0Cyau2MX/ynOEhypphu+7tPitkoT/Lev1P+ibmZJ6S
         ZnxnsZ7Op2mYOnENqc1fclX1WbV4GYsYn+PfUZekt70+DEypCQJ37kmHd7YoEOew91SZ
         8GAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hebs9Ab4;
       spf=pass (google.com: domain of 3eiyoywykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EIYOYwYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id e6-20020a170902ef4600b0017542e23802si8075plx.4.2022.08.30.14.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eiyoywykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id v8-20020a258488000000b00695847496a4so718432ybk.19
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:09 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a25:31d5:0:b0:677:28b:1451 with SMTP id
 x204-20020a2531d5000000b00677028b1451mr13217805ybx.437.1661896208990; Tue, 30
 Aug 2022 14:50:08 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:06 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-18-surenb@google.com>
Subject: [RFC PATCH 17/30] lib/string.c: strsep_no_empty()
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hebs9Ab4;       spf=pass
 (google.com: domain of 3eiyoywykcxulnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EIYOYwYKCXUlnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This adds a new helper which is like strsep, except that it skips empty
tokens.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/string.h |  1 +
 lib/string.c           | 19 +++++++++++++++++++
 2 files changed, 20 insertions(+)

diff --git a/include/linux/string.h b/include/linux/string.h
index 61ec7e4f6311..b950ac9cfa56 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -96,6 +96,7 @@ extern char * strpbrk(const char *,const char *);
 #ifndef __HAVE_ARCH_STRSEP
 extern char * strsep(char **,const char *);
 #endif
+extern char *strsep_no_empty(char **, const char *);
 #ifndef __HAVE_ARCH_STRSPN
 extern __kernel_size_t strspn(const char *,const char *);
 #endif
diff --git a/lib/string.c b/lib/string.c
index 6f334420f687..6939f5b751f2 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -596,6 +596,25 @@ char *strsep(char **s, const char *ct)
 EXPORT_SYMBOL(strsep);
 #endif
 
+/**
+ * strsep_no_empt - Split a string into tokens, but don't return empty tokens
+ * @s: The string to be searched
+ * @ct: The characters to search for
+ *
+ * strsep() updates @s to point after the token, ready for the next call.
+ */
+char *strsep_no_empty(char **s, const char *ct)
+{
+	char *ret;
+
+	do {
+		ret = strsep(s, ct);
+	} while (ret && !*ret);
+
+	return ret;
+}
+EXPORT_SYMBOL_GPL(strsep_no_empty);
+
 #ifndef __HAVE_ARCH_MEMSET
 /**
  * memset - Fill a region of memory with the given value
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-18-surenb%40google.com.
