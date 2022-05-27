Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB4V7YOKAMGQEUBX6DXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C08853640A
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 16:28:03 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id bc17-20020a056402205100b0042aa0e072d3sf3148471edb.17
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 07:28:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653661682; cv=pass;
        d=google.com; s=arc-20160816;
        b=JT70I/8beAdg3e7P/rIM1aRMhirVL4MYlEkY2nJoe1tdH9MNHh5GKomjXVAzgC/nG5
         4rHQdmayfrpUr0AjF8mlE2gEbIm+MCIyoUWyIGKPM+fTxpp0lWcxa0nLr/rVljNacULw
         CSRWUTh1rV2XvvRVXMNDSF97oaU2UxQRub23TfxqX5jpk9u7xnWXHEiY8LbDbGPf9ObG
         IABjYT3uYqf1PRcFV0/tDgwRY5CdPfL+X3It4q9ubWp75NJd0Qu7FAYnFKR2TSd8nQsK
         6bHEd0oDHjMqs3GCDNuPVLGsUhGcwlKkJoDlGpd4LwlYQYeIAch0sdJ3ckeIsOSFdxPv
         JFgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=KADuR6D4B1XNXUa8tFeXzc1o3fegl9e74zUWIfucuKc=;
        b=j1GA3im1Lgn5d/ZQRRw8XwZt7xJKq5Mo4W9adfoyKuEehQH4/Fe38ccDpHqiZWaFcj
         2HuCdsKhHSILWv0BHe/TxP/IiwR5aBnxGT1tTNrc8wrCKI3ICCWikkTBWtY1zjCxFUNA
         PM/slLYBv0HbmlSM6NM7MG7GIm1KrRIDLqb0omMmKpPmm31ZgCP0wiHlvpsnOA8nhuwr
         ilXVmxK52SN3xU9d/4sV0QgbaWv+yU0JbvTPrIkK4wFAZ41jwTiFHnIVSTuMuXx3mt9H
         7N2AlEqUurVobnvyTnzqN8qU1UGB0StHlFNaQ+fh2VLBfl0BoNbeDb06him1RDyBSfXf
         x7jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=iaMXQH7g;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KADuR6D4B1XNXUa8tFeXzc1o3fegl9e74zUWIfucuKc=;
        b=I929Nj3rFSxm3KWC5o5U6313jZyKfplfzNrmPczSUwdwLL6Q4MssGRdI7x0gTdwhvL
         eyDLqIreG+C1Z9xXgWmiPqdY9x3cnGMzT7OYmkjmfvfHTOgSHqKo/wJLjeCmS3YLb5oQ
         BhnEZyxaM3RaoAomFGZd1n0/mxERx67jVcsG5E9AVJTOaiu8MK6qPqHBrC+qr5n/f8HE
         57QOdSZYgzNIYnF0qAmJuiObERu3TwxdQG0zu9xY4ccYLi+TdimzTd1jF6CCkoHHlT7X
         yKhuVQcnAdxvzdetcljsjL8vMaPhM3/Ruehg6aAwB7St0uNSz0Cnm6evB/ycORm+08hh
         fz5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KADuR6D4B1XNXUa8tFeXzc1o3fegl9e74zUWIfucuKc=;
        b=EbNzht8u3zKoiRtU2HovQ+PjFoQ4iJHUdSqzUuOqnLgbOschIKsqR/KtESKHy1+Xkw
         dhrsDIRLfm6PGfftjLaZ9tUXNPdHkTzgCRTcpy3rUzCJWbTFZcqXWL2DHLoWvi9pkzFL
         k29vtRxEB8lrFnVHgbZOjTJwyBzAbPSqOt5PErJNagkGMTdEtVPOJUxRGnr9SS5638eW
         QKrfnY9pQP+IP2PfnXcn3UssgWB8VB/Y0HXpdyShMuhdmAlnuOKzAqt8Qj/4P1Y/vGXu
         Ew8JJedAyayqr3/gb4b/D1sh7aK5eGeiySuXG8TPc1Cge3uXtqy90j5GuvBNV3qdre64
         eTWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KBDH3q5q2s6AF8hVieGTqegGXhmJSraj18qOE5mN8n8vHlee9
	Hq1W9BPocYHS4/CEj3yPW5g=
X-Google-Smtp-Source: ABdhPJxyTKb0CyI62i0KrmnrSJ1qLqVrTksFtQ8JRoyjgnvSriNXV9ctPxHLLSqWqU11a1J5Jnqd/A==
X-Received: by 2002:aa7:dbc1:0:b0:42b:77a2:4f81 with SMTP id v1-20020aa7dbc1000000b0042b77a24f81mr22985062edt.287.1653661682472;
        Fri, 27 May 2022 07:28:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95c1:b0:6ff:45d:c05d with SMTP id
 n1-20020a17090695c100b006ff045dc05dls7294543ejy.5.gmail; Fri, 27 May 2022
 07:28:01 -0700 (PDT)
X-Received: by 2002:a17:906:2883:b0:6e8:7012:4185 with SMTP id o3-20020a170906288300b006e870124185mr37710705ejd.204.1653661681496;
        Fri, 27 May 2022 07:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653661681; cv=none;
        d=google.com; s=arc-20160816;
        b=DcMr4IpR+WzrB2bABfGZ+IMD6fyoEkPkYKEnKjmEFfdJ+DCpeREpENq3MYdpk/7eoQ
         B7t6qfxCrXN/N61TKiyNIaktwZJdNoyWZ62rjSy0eVvI2vn06ByHtMzig9hXdayPMsit
         Uo9TaoMWSo5c/G8xbrP/mZ7gIdMhobH+VU0Hvo6u6H0gzETtnZi0g1unOxOf1R14wn/T
         VLDUBKYJsnFfOKpx20Em4lxVO4FYSresq7uO1xCeO4aNLMGI6lhBLdLsnKEoqn53CR6h
         sIvvpdnQY02YOUWKQv8e9gv6u1qNSVolmFprlIqq5Q6wR9fY0TDvbr08qWfa32upwViC
         g2NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=7341L4ChNBrKLI/4kTfzKe7cMWslrU4u2g9ALhgh9pU=;
        b=KRWX+FUmgZp9Kp80b5BIC82ibb2Ixs1gl8Nx4D+ES7TBnyASNZV5CqCaRYXarx7vuN
         IbqpLqImVsd9OydM7jKk1oXjAkY8RixQIeG1Qe5mqF9nL4QiPPE6ZVgPf38O8qDI+EBP
         74R/1Viwf87G5ZNS7TtzfRDKQca3+bRJ5t2UzU1HVEaTIsmxQAnhUKr7SE74zNZ8lQL4
         0zo4expXWqBIN4f9UgLDaxpK2bD7vcG7v4hinhy16K2aeb8jOC2DrHNmOmbQl00X4PV/
         8XcnZa4GrZrJJQw24qsc03VZIWm+tBUZ8LxCCN8Kr6RMtM1afaq5O28j5OgG34xVBZOC
         Uv1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=iaMXQH7g;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id i16-20020a05640242d000b0042b8a96e45asi232226edc.1.2022.05.27.07.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 07:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuawW-0064cA-MV;
	Fri, 27 May 2022 16:27:56 +0200
Message-ID: <5eef2f1b43c25447ccca2f50f4964fd77a719b08.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Brendan Higgins
 <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-um@lists.infradead.org,  LKML <linux-kernel@vger.kernel.org>, Daniel
 Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 16:27:55 +0200
In-Reply-To: <CACT4Y+aH7LqDUqAyQ7+hkyeZTtkYnMHia73M7=EeAzMYzJ8pQg@mail.gmail.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
	 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
	 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
	 <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
	 <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com>
	 <134957369d2e0abf51f03817f1e4de7cbf21f76e.camel@sipsolutions.net>
	 <CACT4Y+aH7LqDUqAyQ7+hkyeZTtkYnMHia73M7=EeAzMYzJ8pQg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=iaMXQH7g;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 15:52 +0200, Dmitry Vyukov wrote:
> On Fri, 27 May 2022 at 15:27, Johannes Berg <johannes@sipsolutions.net> wrote:
> > 
> > On Fri, 2022-05-27 at 15:18 +0200, Dmitry Vyukov wrote:
> > > On Fri, 27 May 2022 at 15:15, Johannes Berg <johannes@sipsolutions.net> wrote:
> > > > 
> > > > On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > > > > > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > > > > > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > > > > > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > > > > > rather than just showing the RCU callback used for that.
[...]
> Humm... I don't have any explanation based only on this info.
> Generally call_rcu stacks are memorized and I see the call is still there:
> https://elixir.bootlin.com/linux/v5.18/source/kernel/rcu/tree.c#L3595

Oh, that's simple then, UML is !SMP && !PREEMPT so it gets TINY_RCU
instead of TREE_RCU.

Unfortunately, it's not entirely trivial to fix, something like this,
mostly because of header maze (cannot include kasan.h in rcutiny.h):

diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
index 5fed476f977f..d84e13f2c384 100644
--- a/include/linux/rcutiny.h
+++ b/include/linux/rcutiny.h
@@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
  */
 extern void kvfree(const void *addr);
 
-static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 {
 	if (head) {
 		call_rcu(head, func);
@@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
 	kvfree((void *) func);
 }
 
+#ifdef CONFIG_KASAN_GENERIC
+void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
+#else
+static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+{
+	__kvfree_call_rcu(head, func);
+}
+#endif
+
 void rcu_qs(void);
 
 static inline void rcu_softirq_qs(void)
diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
index 340b3f8b090d..aa235f0332ba 100644
--- a/kernel/rcu/tiny.c
+++ b/kernel/rcu/tiny.c
@@ -217,6 +217,18 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
 }
 EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
 
+void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
+{
+	if (head) {
+		void *ptr = (void *) head - (unsigned long) func;
+
+		kasan_record_aux_stack_noalloc(ptr);
+	}
+
+	__kvfree_call_rcu(head, func);
+}
+EXPORT_SYMBOL_GPL(kvfree_call_rcu);
+
 void __init rcu_init(void)
 {
 	open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);




Or I guess I could copy/paste

#ifdef CONFIG_KASAN_GENERIC
void kasan_record_aux_stack_noalloc(void *ptr);
#else /* CONFIG_KASAN_GENERIC */
static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
#endif /* CONFIG_KASAN_GENERIC */


into rcutiny.h, that'd be smaller, and export the symbol ...

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5eef2f1b43c25447ccca2f50f4964fd77a719b08.camel%40sipsolutions.net.
