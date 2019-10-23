Return-Path: <kasan-dev+bncBD66N3MZ6ALRBUH5YHWQKGQEHFVC7EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 54E07E207D
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 18:24:49 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id i20sf9332473vkk.21
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 09:24:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571847888; cv=pass;
        d=google.com; s=arc-20160816;
        b=cbE89bp5e64bjKyfOZWOjiegmiRq01U4vhaWefNjvN1fHoq5BHT2Qa0oc/FHa59V4z
         h3lbYtOK3jangtZ3nFRtCqATagXC/18atgMiKv21tpNkAAflj1fdadvG9EUi4y6+PNK1
         9cNxpwy1mU5frrzd+hTxm7wvmynNlg/rCohHmSDjieiV8kfZdw4B7LwvJ5OVEm7zcDOq
         UCz0/OvBjYLIghtCL+dw9pXr4i4QwKV0K+YNKbaS44BeGhH6frXQicIy3Ed31cNYzBsC
         AQGBdio8cHChPGzPaMAirWFXZGvwmhby9ePKFjeTIp0C5BFe+z0ngKTAdn5ulThNL7Ns
         oXow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=Q7Mt5uqFwIDB2tmqXQLdmqzeMqfwFMVKfMeed2rBOT4=;
        b=YBk9i+DkV8tp+qGv4iLd/WTUdKE17DdwgTcujCrbB9uLaDUTmNYoZqIBxreLIthKdL
         L8RPdunCb8xCGLp540n6LjQvvIzBIItZtoq3r5pCD8hJJcPZA79qIc13Trt5zbqC3q7U
         i+TjL2tFeJlWZVotSedITYS2n2E33MGKKokI0P7K3RzHTeqf/dZH5X/dHSsAfft7qRzg
         MSIzP8WJOsxYnzRKX1w//9mBpWN+D6SUtRpPASoraS3oDOD7meufG1O+04mjhaK0fg6V
         9K/a4wv6Q51+H06TZrmSOGv1WlVHhyUEkpAPhJJV8fpsMngaygR2xQYbtVrtLONchLIb
         7fEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aRXrGlK6;
       spf=pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:user-agent:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q7Mt5uqFwIDB2tmqXQLdmqzeMqfwFMVKfMeed2rBOT4=;
        b=bM2oYHpmYEDi60/9dWekkjoEhoYvYLec/pKSH3OHt08TF1Zfipyni0foOIhL85zAo2
         sCoMdhg35trjgwu1VaxdvyRpPnNcRiyMmpCFMdBxqo7XNXOBBJvk5LX6f0bZNgrt4O2T
         XYPiHkfvHJFZO/zI6o+R96JtsamdNE5e2BCc/4c2Qi+FmB1+YBtzvSJ1GQE1ZM/KT5f9
         ui2daPbHZUdquF+CRwk6v9fZVQre7am0+1lg4qTPhMOEQoz0X/p/zQTeYKdpWAN6HJbb
         M1StPQ1cFl9lYD86Jh2CNwWOJGqKkNIE8u0gKCg1b8C3et5kYPgZ5XhBj3b54g0/rsF0
         bKTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q7Mt5uqFwIDB2tmqXQLdmqzeMqfwFMVKfMeed2rBOT4=;
        b=l8rrJvBaqF7o5v3ZYMIVrNOEAKEnKh+lFMU2V3wYV/OQNzmXhvZ8sa2rhEi/0ubaGY
         8bnqG57eIq0yT3d0ap5GXIo4voujAmKGPsrpSqEcMKC9Skg9liW/emYTvDTfT7wIkhxQ
         EWMQqHeznlrlr/sCC50H3ZUDtLHo+LNIYf37hB27G2c81bdHkDyzlTIE9qYLd7u5bcQY
         u5Ybo24qlOMTm+uRMBL3dEJhmzVqRIS/VQogBfnitOQwy+Esd78OkcXX3voUXlVREjWu
         uEES4mX5HOz4ZjkDAMEFlstAoMk1EGTmguz8R05xqj0I0QI6gp4Vl1Pfx9tjCxB2a/GU
         n+Mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWvdwEASqaXOrZPigKpJPqjhcklcOFTs3EqMfs2j+QZkrwfb+L7
	YNv76y5JqUDVzlMFo/Fy+fI=
X-Google-Smtp-Source: APXvYqx7PI9mf/uO1UKr8P1lGgF5ixM1IrSCnpAVqk0RmEN1stXL3l7GvYFFl57OumeJwwWGLnYjXw==
X-Received: by 2002:a67:fb0c:: with SMTP id d12mr5702825vsr.201.1571847888264;
        Wed, 23 Oct 2019 09:24:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:64c3:: with SMTP id j3ls162656uaq.6.gmail; Wed, 23 Oct
 2019 09:24:47 -0700 (PDT)
X-Received: by 2002:ab0:6409:: with SMTP id x9mr5883464uao.29.1571847887832;
        Wed, 23 Oct 2019 09:24:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571847887; cv=none;
        d=google.com; s=arc-20160816;
        b=MW/gEHp+J6CBS73oAeCtIS34hRO5GnAtTE8OrElEDz9bizbncPA/cxh8hQOZB0On2v
         tRZwOviLrQmq9LzK/F9MMMD1nqtWYd7ahue0Nz+p/hiIfqjJMMv+BLPlBuISZkPsFYo7
         2CbHZV512VQbZ399OW1tPQ3HC8I4e9YizBVrSY2l+jQ5/ilNHe5GA5ukGa+kGCiloxgx
         SNLTUUKY0qftQd0qxSgyQ7ThUw0TdIhk9w16viOVFMV7ePZ3QxDy3FFlW2kKw/TKy4jF
         vwOZ7lCcVM4c2dJbl1+5gCTws8L5zhH8V+HpEGkchmIwkKeFOAnc5OzdRZsDENQMW2Wx
         +KAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:content-transfer-encoding:user-agent
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=eanOm+wc4jMiTMvGZZMqtnxXgjKabvAJwYAPnub5fDU=;
        b=snUp3guuNHHOrD8XWwRFVPPsxLyFBLeSx8aqWpBp3SW2qowsYMpK6q28rQxwF4msZG
         2M87R42GsVLsmiErxxyvTLXaiHJz5jyyQ3W4mzMSFGubt35Nx2LnTERZXGyw/ACjtR4s
         CNYSMMZZl5Mevd6VIxfhi4z4zsB6N/eq1J6gLriSrZApJdrGyyVkNba/Gm8ptOqGUFJt
         DFXsAE963QobzGVM8BDTQhYr/bdvYyzSFWe69k6SQL8/gtuKdoWN2pgNUpW5eVeiwB6y
         Is8SBWQN1V26fWFHkpIerLvpVVUwIWows3ePHxgqF1HHWLKGABts5wU3cDk5sWmJYGbE
         BcoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aRXrGlK6;
       spf=pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id p78si256202vkf.0.2019.10.23.09.24.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Oct 2019 09:24:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-361-nn_WxBf4PueDGKR47J5rTQ-1; Wed, 23 Oct 2019 12:24:43 -0400
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id EB51780183D;
	Wed, 23 Oct 2019 16:24:39 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.43.17.44])
	by smtp.corp.redhat.com (Postfix) with SMTP id 364AE6362F;
	Wed, 23 Oct 2019 16:24:33 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Wed, 23 Oct 2019 18:24:39 +0200 (CEST)
Date: Wed, 23 Oct 2019 18:24:32 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191023162432.GC14327@redhat.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-2-elver@google.com>
 <20191022154858.GA13700@redhat.com>
 <CANpmjNPUT2B3rWaa=5Ee2Xs3HHDaUiBGpG09Q4h9Gemhsp9KFw@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNPUT2B3rWaa=5Ee2Xs3HHDaUiBGpG09Q4h9Gemhsp9KFw@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-MC-Unique: nn_WxBf4PueDGKR47J5rTQ-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=aRXrGlK6;
       spf=pass (google.com: domain of oleg@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 10/22, Marco Elver wrote:
>
> On Tue, 22 Oct 2019 at 17:49, Oleg Nesterov <oleg@redhat.com> wrote:
> >
> > Just for example. Suppose that task->state = TASK_UNINTERRUPTIBLE, this task
> > does __set_current_state(TASK_RUNNING), another CPU does wake_up_process(task)
> > which does the same UNINTERRUPTIBLE -> RUNNING transition.
> >
> > Looks like, this is the "data race" according to kcsan?
>
> Yes, they are "data races". They are probably not "race conditions" though.
>
> This is a fair distinction to make, and we never claimed to find "race
> conditions" only

I see, thanks, just wanted to be sure...

> KCSAN's goal is to find *data races* according to the LKMM.  Some data
> races are race conditions (usually the more interesting bugs) -- but
> not *all* data races are race conditions. Those are what are usually
> referred to as "benign", but they can still become bugs on the wrong
> arch/compiler combination. Hence, the need to annotate these accesses
> with READ_ONCE, WRITE_ONCE or use atomic_t:

Well, if I see READ_ONCE() in the code I want to understand why it was
used. Is it really needed for correctness or we want to shut up kcsan?
Say, why should wait_event(wq, *ptr) use READ_ONCE()? Nevermind, please
forget.

Btw, why __kcsan_check_watchpoint() does user_access_save() before
try_consume_watchpoint() ?

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191023162432.GC14327%40redhat.com.
