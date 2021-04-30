Return-Path: <kasan-dev+bncBCALX3WVYQORBDNDWKCAMGQE5IILQ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 83EEF370400
	for <lists+kasan-dev@lfdr.de>; Sat,  1 May 2021 01:23:58 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id y20-20020a6bd8140000b02903e6787c4986sf34726274iob.23
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 16:23:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619825037; cv=pass;
        d=google.com; s=arc-20160816;
        b=buSLMGok6e7rm/YwmGcP8B688413JrNpzgrUDLAKDYMVAzpCE5N4Wp15rZATT3aSAD
         PWIRPrONfsDXgHwN0TtlurTQ3u9pQbnVAXSuBClTS/28yrY+gQsjL5DvFyy7xGBQEssr
         Svq21T40byDUCgmFfZZYxX5Ls8A47CxtbM1Mxcw4uZsPD63ATrJAsp7vHUXvbLUGb4St
         4kP7zmqf2I972O6H3cleOu/bbYrIJzSRcwPciwsjBlQHmy4X4K0wTOvjDbngX7y0Tpbe
         IOG+njC3U1avLKEGu9Ikh9IMcUsxV9UJiLYyWz900bIiUWfXzpIliwYPqVE1km1l3yRu
         uavA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=r2mRfszzPzqYMs1HHMmIlLayGK3H1U+JFPyJo9cFJjs=;
        b=xvzpgdPkY8xbAI8XvY/P96tr0ZumPyJK2qpnB/FZr0ChLMwPXDVrvSxkaCpzE6gHxt
         HYIr/TRjQirLRBx6zsMtBJEHz0BWcjJ3WTUV0N0gE7NOOZJ4qClJqjnHdQG8dBdWLcbj
         1ZHl/YBEHaZSnwGwIXUGNn/LtA7aUH+g7uAGORAjY563t5CLVxF551CnUpmJAkME0mT3
         FNE0Ypg9IY86/DIIsbN0jr/367xEg7PP8KQ0ChmNBCU0SRVLmB2dpzvQfhr/1YYyUudl
         iTzX2NmOMT46tZaHNZZQYmx8HH8nOds93UzeVoPN7RCQWxmbw3csOqQc3ht+WS8FKejU
         pXOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r2mRfszzPzqYMs1HHMmIlLayGK3H1U+JFPyJo9cFJjs=;
        b=lCtGHBepqoxbPYhrFQHOa00iF23SSLT20KLjW69fVcfLUbH/trFH5F1eoH+r+tUBOC
         wVaG/FqrVyIr/du0uDQFuXbTwswMlSN6blxbK0o742rlxeIiJGqCf8iKTDbZSww37GHl
         2UKqMm6t0/+2RgLJr91oSHh/1BTvEiat08ZNQdS1Nwhj+5RwWmd+I5YMGOVplByKsdbJ
         vd+Nb4nSTfzBxKy9o1uxcO6Gk3esg2gbvvKPbDT7M7tv34HtBxtcvuHgNm5kIiLjnE2Q
         a+h02pmPHTO6rlt+hFbZvNUVZ4W1JsbQw1DwDwIlESZmmJVyUNmg6wPbJS0wJz4EcCqO
         A60A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r2mRfszzPzqYMs1HHMmIlLayGK3H1U+JFPyJo9cFJjs=;
        b=jpy5YUcTRxCnjRD5RkxwT+FblzYAZOeadcvSeLQa824quozHe9qcVhj+ABj4s+CIlY
         v+1tquNbP6emvaNiSamJOahFnq7mkqCF5M0n0Al6kC/1aZrptHqb5nOAIMz6UHRMh9pc
         5qa50Hja5C2n6YQL5R9rXzEe6JapLJtn+G0SOokZl/mCs+aP9pEhvr0dyWbJF8soErpE
         JN+VsLMV/sePZmyBtEqFZrQuY1i6SRFEyj6hoZH70GwVQUqym+nZrB7ha+T0hl91xZHA
         FxyFy6PqMfWoj8qI4iZDHq1wfCM/4tSKDzH0ywHsMEWDvHMBVJLnoymwh5piwyicg9EE
         Ui7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RR9JRArw49rdzINrjw77q77CjmOxOZPhR6OYAOwTZ/f0bZGE7
	K4xKtDSDf5INSs+pevvj0yM=
X-Google-Smtp-Source: ABdhPJyANBfHDJ5nmCa2BQ+31E5pCp0BurgHvqxPScxq1WjOuja41jdVkQLdoAwP7F0LxcxugwOXWg==
X-Received: by 2002:a05:6e02:1aa9:: with SMTP id l9mr6124735ilv.24.1619825037414;
        Fri, 30 Apr 2021 16:23:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3842:: with SMTP id v2ls957572jae.2.gmail; Fri, 30 Apr
 2021 16:23:57 -0700 (PDT)
X-Received: by 2002:a02:84a5:: with SMTP id f34mr7186324jai.50.1619825037016;
        Fri, 30 Apr 2021 16:23:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619825037; cv=none;
        d=google.com; s=arc-20160816;
        b=LDI/nhH6rg97L+2QoFPCroqEZ6lJgtU25LogX6oudKZedh/AnwDxh9NACAVywfnf2F
         WSMtFftdT/oKQuoe7a7hgzVIZWS145TnmZ62lQj8UdaDcU72Hu38su6XFrL2p5Y2CIuj
         xNZIq38mZ/CeCVP27F8P9o3Uzt75j3F8K8+swkL4vxAcnDYYcvuBIHayV2CWvqmpHZNj
         HBSBwEeXfXdF4oEnRFvAuQ9ltYvRLGQ1PXRh6YtaN5Cgbt/Xsg/jnVDDEHnGIE91No9W
         tvE4zBk2ALZLMq3AcxPzfjXwZX6Nydo1IIVARc3dOqCp6ItRkZCZ9sNJVUrw+UIsQcDL
         nP/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=e6IWfda0frC/sPHJmgOuTzPJ9sdpOieugVZmqvfxZ9Y=;
        b=ogPxiXNUjtMW97Sij9GlTNaLAHRuCxj+ZZEjfpurNRpdjnw138XUqHndGao4zHfs09
         B7nAptV47h1amT6bW7KNmqaG1N9iY5rpjCQzx3dIAUr7YwPC9xfxenQinTMjd5+e5ESm
         5ctqY4pV4xLa0/96RaueAbfQGMSux0Iky3SqW2GmaXCWb4PaliaB4bG5lrQ286CO1stc
         dLlFwOTVJuGraWtxr8/gJ+jPBuJDeaZRrC5Wo3f0wGMdg9K82+r3BWUPbFsm1f3nQkJ/
         NUR+xyNoDZ+bL4scBBqO0RYlkFZd0M9qoJg98HL7fb/0VY44KTOTnEPvWbWubegGQ5Lo
         lTjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id j1si788227ilq.0.2021.04.30.16.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 16:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccUF-00CsoG-Qp; Fri, 30 Apr 2021 17:23:55 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1lccUE-007HaN-Pp; Fri, 30 Apr 2021 17:23:55 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
Date: Fri, 30 Apr 2021 18:23:51 -0500
In-Reply-To: <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> (Eric W. Biederman's
	message of "Fri, 30 Apr 2021 17:49:45 -0500")
Message-ID: <m1im43qrug.fsf_-_@fess.ebiederm.org>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1lccUE-007HaN-Pp;;;mid=<m1im43qrug.fsf_-_@fess.ebiederm.org>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/xW7yT9MZRBfGY7mc5Y3fx4buEUPwx95M=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa03.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=-1.0 required=8.0 tests=ALL_TRUSTED,BAYES_20,
	DCC_CHECK_NEGATIVE autolearn=disabled version=3.4.2
X-Spam-Virus: No
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	* -0.0 BAYES_20 BODY: Bayes spam probability is 5 to 20%
	*      [score: 0.0621]
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa03 1397; Body=1 Fuz1=1 Fuz2=1]
X-Spam-DCC: XMission; sa03 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 286 ms - load_scoreonly_sql: 0.03 (0.0%),
	signal_user_changed: 4.5 (1.6%), b_tie_ro: 3.0 (1.1%), parse: 1.04
	(0.4%), extract_message_metadata: 2.8 (1.0%), get_uri_detail_list:
	0.72 (0.3%), tests_pri_-1000: 3.9 (1.4%), tests_pri_-950: 1.24 (0.4%),
	tests_pri_-900: 1.01 (0.4%), tests_pri_-90: 83 (28.9%), check_bayes:
	81 (28.3%), b_tokenize: 4.2 (1.5%), b_tok_get_all: 5 (1.8%),
	b_comp_prob: 1.29 (0.5%), b_tok_touch_all: 67 (23.6%), b_finish: 0.71
	(0.2%), tests_pri_0: 173 (60.5%), check_dkim_signature: 0.36 (0.1%),
	check_dkim_adsp: 2.6 (0.9%), poll_dns_idle: 1.24 (0.4%), tests_pri_10:
	2.2 (0.8%), tests_pri_500: 7 (2.3%), rewrite_mail: 0.00 (0.0%)
Subject: Is perf_sigtrap synchronous?
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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


I am looking at perf_sigtrap and I am confused by the code.


	/*
	 * We'd expect this to only occur if the irq_work is delayed and either
	 * ctx->task or current has changed in the meantime. This can be the
	 * case on architectures that do not implement arch_irq_work_raise().
	 */
	if (WARN_ON_ONCE(event->ctx->task != current))
		return;

	/*
	 * perf_pending_event() can race with the task exiting.
	 */
	if (current->flags & PF_EXITING)
		return;


It performs tests that absolutely can never fail if we are talking about
a synchronous exception.  The code force_sig family of functions only
make sense to use with and are only safe to use with synchronous
exceptions.

Are the tests in perf_sigtrap necessary or is perf_sigtrap not reporting
a synchronous event?

Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/m1im43qrug.fsf_-_%40fess.ebiederm.org.
