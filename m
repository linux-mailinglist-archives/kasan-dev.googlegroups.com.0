Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW667L2QKGQELGY2OIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id E8DA31D52F3
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:03:56 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id p31sf2753186qte.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555036; cv=pass;
        d=google.com; s=arc-20160816;
        b=CI32IQNp+tvdKlhW/9g4gKfMa8AVP5Lgs4Ptuxo3M+OnTeTZa4c9Wr+CH3z8iBSwAN
         MsLHvvdFQPqjdlyTwyL5IXd9B/cFggAvM0BjVulo8rEH6C1kSSSdacxqbkdpZClD7w/g
         fgxq8UKAWpFDN4tGwHt76GcMYRkXJDaZ6s1DUaVQhaGxCaAfGres/7AyRTX7csTEXNCA
         OF0kegpSZfJCFXEJXLJcMlt+oqlVwbb/ntcXFMl3quEk/hob2XSIcie/Hk0I2oBivypz
         8cornoqPOPDszAkbe96WXmb4Z279oFax8QuML1sMnX7mH+sKdoLRxJIoNHGkmg2EENCz
         4QKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=v1FXKn1yF71MK3npGcadA/5lecNMmRgXHSUV20XOnoc=;
        b=D5WW0yN1iHENIvG4wvPwAFAh32uLHIztZetqXTrRUBMpYeFz4Db27a09FnoU/MfnLn
         qTkxpy6KJL9sdY7MvPYr/d/fTTu07MqAs/vLiaQvWNZ0JDVQ77WE8DMpui+MC2CXCH88
         90kCYz93Bbah4pVFPkJfN8diFNIXYKZJZb0Mlm5Ay72xR6tacbr9I5Oid+Cbn0eWqAno
         LLuXvhpEErldc5jxGVFtDovrDdQF7HqaCcNqZ3PtqIF2F0r/lqPz3GGQdquOGcs+kHfJ
         DUCsMTmk+IAPSrcPsO8gj9B540lGWPGAqd9DABX4QQzJ0rpFXSoBuk7PA9Npb20ooFyf
         LlXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CglnwgQ4;
       spf=pass (google.com: domain of 3w6--xgukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3W6--XgUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1FXKn1yF71MK3npGcadA/5lecNMmRgXHSUV20XOnoc=;
        b=TZV0hFhqA4Ly/zZTpQTeXGzIwJiFYwCJNNKS5A5H32w7XDaRr1Nai8CJyEW/VNVXod
         Kpl/dHb2AdZgVi2HiZY1HtOYnJ1ZaIa/prny6HFAo19oDTWOHHP3V/rr01FZePwCJT2C
         OUX3txBmbhbLH8AoRr3cqwU5/FRBAyQ2gW1MS6qKShxN9+ILJyujJjopv/WAafA4+rkY
         FJ29ddEgJHkilJRdhI8PB8Dl24aQ7kbHo8jcYYlLuPCO63MXZazhEzqrfY7sYy0N/5I+
         +MRyPMxH/whO4Hxsjz4gTvrqO8jgiwaUJQTiODH27xEmbFx+WvkafBhV8/rxOJ+91bCQ
         n84Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v1FXKn1yF71MK3npGcadA/5lecNMmRgXHSUV20XOnoc=;
        b=IETi72B88R5JLp/5L+CeS5IOKZG3KXdVHWuCd7nVVlvNv1ucJ0tZOKbHyejC+sxDtB
         4jjDh7p163TnNJsgBOdQCeoloknekJZY440QnK+dm9Y0Mwy8gpEkTCVT4mcyB2AfAHUw
         vgfCAlPxWLGSF1Z1qr1r0CpxR0P2hjlSl9VlOuIhj5tbK806K8/WT4RFSirEc/Sm+/UD
         mejLkTqTE/pI1waT7vAYtXo/2g55E+y1v+I/sT/JJc+vWQFhVNpW6mIhZfCCAoibFDXD
         PjBL1z0n3E1NRgUEFGs/Yu6jXvi58ag8BAfFiveuP7YKQehjTCJbR2AjqeZGRrBUD8Of
         j25Q==
X-Gm-Message-State: AOAM531pegpPOV+IjO048GGc1tEDvdV2JuEFbJwT7rjPEvdgglip85/M
	fly37onQs6ZNsdyVi+NxXn8=
X-Google-Smtp-Source: ABdhPJxT82X434ZFzzf70mbOrVUsRNRsxJz25nCwjQkqWkeld7oPKdieZHgpRTRXzOV3rqjmGsMo4A==
X-Received: by 2002:a37:c20a:: with SMTP id i10mr3764116qkm.29.1589555036027;
        Fri, 15 May 2020 08:03:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e53:: with SMTP id e19ls964348qtw.3.gmail; Fri, 15 May
 2020 08:03:55 -0700 (PDT)
X-Received: by 2002:ac8:2dd3:: with SMTP id q19mr3868379qta.308.1589555035560;
        Fri, 15 May 2020 08:03:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555035; cv=none;
        d=google.com; s=arc-20160816;
        b=HiZDzWeUEIpOKInLLVozWh5zRVNZ5Qc14+/H1tRrSl1tTK6Jk7lnqLRJWxFo3hvxh/
         SnQxcojaHZACFw1i+Oh0YZZ7+O1Csw8hApBS2ZhyVThHVKiIV0D4Brsbh0HaqZX9u3FK
         3TzPAYpU4U7ExZPT2WpaBhBF3q7NkmcihuInLnPgMV3751m8WsbyMb3JlujBDm6GDYZQ
         mJPqUtQ4Ljt0yZzv3wb4DhSzHJ89QqBHYeTLu74W236FXAAE9cnGUutTEDt87LxTimjH
         sbbsAePdlIebcP/WkMAJTF4Z29mbcWZK6GEHwTyMR6fS0WS8a+N/YpEsAXppihjCs3fI
         72UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2TmNDvsOz0JxdxozHkAyPP+/TkRXJhNAPV4NJ14stug=;
        b=m6d23KiK2L5frGPW03qKS3TI7+T1IIUyt/0zPRdyXisUZTKXlM8sZmY63ACLajXGDa
         nauVRbEE1Dse6z+6GPcSW6aqhuPLZtnvSs3MYaZxkG+Ta3BBijBw3ZrEqIVtPDQzJw+X
         OXR9G988pdu3LkTeTXYq3Aj72grnw2UfLIdo12f8B14pMLB4IglBeVIWjMR4trUcV/nG
         u3NhuNX8Dtwbl57IGn/Aferc59/atG8ombxdl6A6EgKHdJlct3sjvjjhQMC7PjwFTweG
         wjn/W0VKtkTB3GuNl9/Cy09AxLXIIuU5SBjdsCzlrQG9CqNejIldPu6rOSR2up0ehJNZ
         zyJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CglnwgQ4;
       spf=pass (google.com: domain of 3w6--xgukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3W6--XgUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id w66si211463qka.6.2020.05.15.08.03.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3w6--xgukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id v63so2508289qki.5
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:55 -0700 (PDT)
X-Received: by 2002:a05:6214:3f0:: with SMTP id cf16mr4050654qvb.4.1589555035266;
 Fri, 15 May 2020 08:03:55 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:32 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-5-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 04/10] kcsan: Pass option tsan-instrument-read-before-write
 to Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CglnwgQ4;       spf=pass
 (google.com: domain of 3w6--xgukcbaubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3W6--XgUKCbAUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Clang (unlike GCC) removes reads before writes with matching addresses
in the same basic block. This is an optimization for TSAN, since writes
will always cause conflict if the preceding read would have.

However, for KCSAN we cannot rely on this option, because we apply
several special rules to writes, in particular when the
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC option is selected. To avoid missing
potential data races, pass the -tsan-instrument-read-before-write option
to Clang if it is available [1].

[1] https://github.com/llvm/llvm-project/commit/151ed6aa38a3ec6c01973b35f684586b6e1c0f7e

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index c02662b30a7c..ea4a6301633e 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,7 @@ endif
 # if the absence of some options still allows us to use KCSAN in most cases.
 CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
 	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-5-elver%40google.com.
