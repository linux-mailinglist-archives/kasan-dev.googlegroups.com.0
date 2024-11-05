Return-Path: <kasan-dev+bncBDBK55H2UQKRBDWNU64QMGQETCG6CTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C9499BC943
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:34:08 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539ebb5a10csf4637037e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:34:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730799248; cv=pass;
        d=google.com; s=arc-20240605;
        b=DUzDf+NYNeBKEllnJ8KvKFoN9pHFzRonqC0xxL/3wB1UOlHQecWMdvoCnz51+UMhKl
         U55q4asyekVVAKKUt4JkFY/0RyJfDeNMvbnLni4GbmKKmUIUyeCDfNTjHu9OeXVs+eJQ
         JPmQ6PA0aX4oMWg8qNNaF14CmpnRSWSMoZJZ6rS6LXJcLjTylpN/UJ3YqhTueujKTQoQ
         1OATL68zNUzrF8vUiJP2Yhi+jARpSBOKmXkMjjlpDnhI8PK61wN9mSSQv+LlXr8xFfKI
         bztCjWH8oOOImZRXjFXlEVjertARCTf8WFdPT8D3BmyBjDo9uAU7ixK3oZshkh/Qsi03
         GsoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2hbddgzTrjTId2AW5TcddwQE22NzIXPWH40l8wvQves=;
        fh=yS2RFAaINZeZlvtpDRsKX95CvfOiDaYzfPFUvXYqbag=;
        b=NDv7ujcljrCqgByOwqY05N3uz/BsIWGc+GK7RJnO3Zy66MQOs/DuTuOURLl0JBuK/I
         7H85e1Z9NWlwlmwSR2OSctI+UMmChAT9U4AHQvDCxu9PBYWW+PmDkcio04sdPi/DyifH
         0fTpjn//wnIHtn3wvle+1YKfFQn3hNGc8blxV2Jc46GdZstcs/ZUYkQoOYGnrpIc599Z
         NWFTz2qYHpCUskJn+WqS+TwzRX+zow9SZuG0PSyNoQ7LdREBpjPrWlIY7lvh79H1v+Sk
         YdidV3wYNTZjhAG2vWRu7Cb9kvnFZikasInlse8YUgdHRki/8qLnCy/5RybhK14N7Ur5
         YwVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Je5WzFga;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730799248; x=1731404048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2hbddgzTrjTId2AW5TcddwQE22NzIXPWH40l8wvQves=;
        b=J6rMwV/bon5vDMpHEB7Nf0PglyEeRJclcu06ojeMbZdm7u9JWBpTlBM8656w5SNKhj
         Ck/JgQPnl3TW6MwojrFwRHYAlLdLj4a5CQ7TtPDDkSBhuDEOJvRCL9vWkWAr0c+pMsv3
         yRElHqmMFO66pAwyUhDxi0Zuiw70KdaA9W70sOeYwMb3yluDHoEnUALX9Fr+gaJuZD3x
         z9g+5JsDQ6Cfe8wn+gZvh4xgG09X7PqsHGgJZV4XSSEzSlRkYGxxGP9G4EKC08t6KVE+
         hIib22UjokAXJV+4czZymUlLYFkY6B3b0FEo2+ZjUqKzlqcZmvkZ11WuD6xIWiKmsgHe
         uFlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730799248; x=1731404048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2hbddgzTrjTId2AW5TcddwQE22NzIXPWH40l8wvQves=;
        b=XpyXbbkFmOfRXRsvK/YYmCk0OysCJ/laa3DNBhkwZwXbnWEZq4UADCQGKg3KQ32JSt
         G7SQvulrjYYYy2+eMySPXCV2bC0v+b+3d7v1MomDaUhvmmlJ0x4ogjTHAHTK/skV2efo
         OBahO2mo+8Uf5qVBrsb3g8YXcIQGdyVZIzgky/ATILxMHdRhD6Wdt808B1FFgiKdliT2
         lxy5Ky/QNJisJecvq4N7Bs72kZxnANuYu5ytXCyIAihIgIqweLlbVC0HIYTtt7i8keo0
         Ea/CkqwYGm/jTEnWlTwHtm5HJ2gcQMc/IkSuTDVJHuf1nHuz4OplLUfpCYXGBPiecFYM
         Pq5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrmkYc/Dggdl3GpM9XqS8CN85AduSYSIT5h8YxEjeqK6sD8g5pVnhRWy3RL3R/waTKWKu6UA==@lfdr.de
X-Gm-Message-State: AOJu0YzXqt64rtVpuWNlaPis8WZdfDBuZa6o7Fa0jLsSKVBey776gOUM
	Vm7BZGEkzqhlXpr/EMGuoIGlT+i+w4fafdkKRwVvCHamZ+bPtAOw
X-Google-Smtp-Source: AGHT+IGPAbalyU+WIi8mfs4/PPTqazGEn+63aQr6s9LjnCPu/4eJA3e5nchOEasOPvztzwqkscUrdQ==
X-Received: by 2002:a05:6512:3b2a:b0:53b:1e9b:b073 with SMTP id 2adb3069b0e04-53d65dca68dmr10929123e87.3.1730799246590;
        Tue, 05 Nov 2024 01:34:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1585:b0:53a:c7:e1a2 with SMTP id
 2adb3069b0e04-53c79201955ls779188e87.0.-pod-prod-05-eu; Tue, 05 Nov 2024
 01:34:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXjhlUKRSQeiTLoeSC7XyDAi82Oyu2sAXp6RmVAdIC1n15GuGrx+hfoA88CUq6Xh6mU2ayGUmgBB4Y=@googlegroups.com
X-Received: by 2002:a05:6512:1590:b0:539:8fbd:5218 with SMTP id 2adb3069b0e04-53d65e168f6mr9849771e87.56.1730799243860;
        Tue, 05 Nov 2024 01:34:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730799243; cv=none;
        d=google.com; s=arc-20240605;
        b=QpbqZkzZwTlp4Q+wPPSkLkJ5m3cty0//+8t9E7IQCGFeZue/iAyO7N78xT6U4ehPym
         dlRiRDUxCWRTTj4JcRlKAi18yLYJQWTPFd0RNlCpGfSGA0JHcNXahJmGZRpYZf/va5K4
         sJE+ya/t/vXtq8pqhU4aPqRbJgTwWrNCzyDXfUVDEScs/AH8k2oWoLq6dd4g9PwLyYuc
         JsUmBu08XOmu3LdFScBfEpLJ8b9SiKyNNQJ+yxyYuroirOR1H8oPolVToBuugIn/OJA8
         MuomfuIcHfR3O6qx/qovYS2TKfifOXy7bxbDvNqXYVFUZ99S6/ykxXoxRm3Pq+dMvDAI
         EQFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/Bs5buUWkBHBsOr2+ZZy1EpMRfHdPjXKx1KmY+SwxDs=;
        fh=HKTbcizfr8o6QpmRNM/kCBMgTgM8xHS3xBQP4RvcwvY=;
        b=c+Iu28H5liCvNHwf5D8AFXwRbM1k28SsyX4zRre4ScMVlqN1ZIK7wNgnpE43gtbx0P
         BZvn+vu6qjEfxpDoN2rs5fZX2y/fJPrnOVyYKdLSiCu0JeFWe9GXTSXKQTVz517UQJII
         Tkb9VdvNG0UuNe5zP/HYaUoMbe5hvtj+sVc4IvG1m/EVghVkAhuSex9asy9aaHzY74p+
         nzDYVAH8kM4FbCC2ljL8TT/tMSYv7fdGMwy3Qc2WBixEkVmD5ROUntrU++Lyoi/fHYVg
         U+K9zE5YdjZiJnEPALlK/FbUYnJ/wJB/nIKUmTWoKuEn6SuMCgpqoUkMALpR8MaZHm18
         5D9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Je5WzFga;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bc961f1si214218e87.3.2024.11.05.01.34.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Nov 2024 01:34:03 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t8Fwl-00000002NjH-48Uw;
	Tue, 05 Nov 2024 09:34:01 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3A78C30083E; Tue,  5 Nov 2024 10:34:00 +0100 (CET)
Date: Tue, 5 Nov 2024 10:34:00 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in
 read_seqbegin()
Message-ID: <20241105093400.GA10375@noisy.programming.kicks-ass.net>
References: <20241104161910.780003-1-elver@google.com>
 <20241104161910.780003-6-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241104161910.780003-6-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Je5WzFga;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 04, 2024 at 04:43:09PM +0100, Marco Elver wrote:
> During testing of the preceding changes, I noticed that in some cases,
> current->kcsan_ctx.in_flat_atomic remained true until task exit. This is
> obviously wrong, because _all_ accesses for the given task will be
> treated as atomic, resulting in false negatives i.e. missed data races.
> 
> Debugging led to fs/dcache.c, where we can see this usage of seqlock:
> 
> 	struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
> 	{
> 		struct dentry *dentry;
> 		unsigned seq;
> 
> 		do {
> 			seq = read_seqbegin(&rename_lock);
> 			dentry = __d_lookup(parent, name);
> 			if (dentry)
> 				break;
> 		} while (read_seqretry(&rename_lock, seq));
> 	[...]


How's something like this completely untested hack?


	struct dentry *dentry;

	read_seqcount_scope (&rename_lock) {
		dentry = __d_lookup(parent, name);
		if (dentry)
			break;
	}


But perhaps naming isn't right, s/_scope/_loop/ ?


--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -829,6 +829,33 @@ static inline unsigned read_seqretry(con
 	return read_seqcount_retry(&sl->seqcount, start);
 }
 
+
+static inline unsigned read_seq_scope_begin(const struct seqlock_t *sl)
+{
+	unsigned ret = read_seqcount_begin(&sl->seqcount);
+	kcsan_atomic_next(0);
+	kcsan_flat_atomic_begin();
+	return ret;
+}
+
+static inline void read_seq_scope_end(unsigned *seq)
+{
+	kcsan_flat_atomic_end();
+}
+
+static inline bool read_seq_scope_retry(const struct seqlock_t *sl, unsigned *seq)
+{
+	bool done = !read_seqcount_retry(&sl->seqcount, *seq);
+	if (!done)
+		*seq = read_seqcount_begin(&sl->seqcount);
+	return done;
+}
+
+#define read_seqcount_scope(sl) \
+	for (unsigned seq __cleanup(read_seq_scope_end) =		\
+			read_seq_scope_begin(sl), done = 0;		\
+	     !done; done = read_seq_scope_retry(sl, &seq))
+
 /*
  * For all seqlock_t write side functions, use the internal
  * do_write_seqcount_begin() instead of generic write_seqcount_begin().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241105093400.GA10375%40noisy.programming.kicks-ass.net.
