Return-Path: <kasan-dev+bncBD66N3MZ6ALRBE66XKYAMGQEAVVI5VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 88026898909
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 15:45:57 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5a486a8e1fdsf1062526eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 06:45:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712238356; cv=pass;
        d=google.com; s=arc-20160816;
        b=TILd/8Av3YW6/svY+HoIp9R9CsmPyfZVGhcKQGguBr00NkaFYVFiTwhmdbCbWdBpYQ
         PeZX93lyxss+Tk4G3zn4T89SB4/ZQ45F3GPAAwnIW3+AZUYrq+vsj2WOgnztKXfLvyd2
         30bf3b78UiyCcmF7wbjFnDtShe42kJ2pzXNADJxbbiQFnr/6tqGoWWDFsLYmlfCKrwaA
         clK/h59rbwAWoRVmZvDR/ceDgdsISVSYAdeJxa/BTLlrm0XbUJnfOfD2w9PSams+bkuC
         KVdwAAm0pXVenf4cwMtmUhUxap+K2qy6H9YAUWTBFVVxDL6W4h6kqIEGzOvqc2fNS4eP
         Z5mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=dEhc7lSCySDQ2A4is2mqgQNNo6JWLCWopRxHPX9V11Q=;
        fh=xMsyi2sbhznUiLZXpZb7MFN+mBIwYkmVsykHlruVKhg=;
        b=Zh2ydRZz7lWEmNea7EsgO5sXc2QGbwQD9IpMzkFQ8YQDeIPfwrqHJa5oOq3eTeDD4r
         9KVtXRLiVM2/HQU9WWxs7F9i8dd6bBW257ltQS5kP2C7FwxzJy3ODxrbL2XSOboQmud1
         wdg8DjdefI7mAuDrkUuf8oQxO4X5oYmKkAeJ8JEwjB+ctAcrB2ceE6RA7/Rn1qJ+gYyT
         DuS6zFmJ8AtzPzRHgP4gVj/UbP77llHhCtN9uumEJoA1SmVbPKw9i083fK5IyhP43KVj
         c8essKpb2wxdZt97t4hlFgrtMtmvVXb1rN3CpVmnkI0IKA0VUD6DKZlP09tHtiL2KCMw
         9ZYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DTBdMOng;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712238356; x=1712843156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dEhc7lSCySDQ2A4is2mqgQNNo6JWLCWopRxHPX9V11Q=;
        b=rp/8IvDary69BKnKjN1gXGZThiC0pFTFkG+Mj0ejCb7WPcRJCUrkeB4u/E0p3yRkao
         Zx0qb3l2JFsArJd1APFJ+yrz7kyC/UYhQqO/dXtN1p02WVjnFei1P6Cjp3gCvePsuIeb
         bHYzB6gGirQT5oKlFHb1RQRdBYyhPuj0Bn8997tx0dZ4lsN2K0c50/MTtXy6z/ZP44Jg
         vCN9zvYH7EWkghno2nsmGtALVpzduRjtiK1AA9SdJ5rtr9WMTvRSKWwQ2JPUx/Wg4mD3
         sCTMUcFdFZHn5IpINIBpr5PA3J7yT0DIqq+GPfL6vT9JwLCeSjStwFp6wmsusTaAGD9K
         doeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712238356; x=1712843156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=dEhc7lSCySDQ2A4is2mqgQNNo6JWLCWopRxHPX9V11Q=;
        b=NUQJNphAV1zEJfCJIlXRxHvmxxbHKb0LVd4NALdflS06yYqX0bsPgyvyMiEf348s7j
         LJEXqbjWmJc7Mnskj645yleyEBA90f7QcXUSk6AWZDOYDDfUS2RIgQ7aa6vnd5mwVQna
         M7/W2lvsu7uKm6f6y7YTRDGNKda/911EAcaioFS9W9SXhh7fPt38pYH+xZYomSYJ1W0n
         3wvDPWW0SYcdVu9GdS/NwKMZJq8Un8XLEYlhqNlOf51wuV0OTJYy10U8g6w+adCLbBeE
         t3A0a/PlfDgg8X9WQcVIQ6RrrPep+37e7B9T4ZXwaHPpUu7Kd+VNGMLFMfxQ8lE1vm88
         /pDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXTz9AX0aPGN8o+BBgUre9JaIZBWh0AxrU2kWKbNmIr/cNdouCnw0DlEo8pzlIlSuV/XXq3uCKMWVEwwa4Lxx+csueFhOqYjw==
X-Gm-Message-State: AOJu0Yz0S3u/vt4gGW9osifPPdVtAkb/d5tydjufVSo3dTBQ5nX2Id4s
	dISouMLVj66ASKoKBByqg++2yn/DZ1HjzJdphjPAhJY4JB9cE/Na
X-Google-Smtp-Source: AGHT+IE4HDQgTmCXZy9oDt/q1kjpWgegqv98UCxDRFBAGsQi7vMWjsMkJsGPn74EQogEHeH6y4sDvA==
X-Received: by 2002:a05:6820:2713:b0:5a7:c78a:2c96 with SMTP id db19-20020a056820271300b005a7c78a2c96mr2413571oob.3.1712238355962;
        Thu, 04 Apr 2024 06:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b0c6:0:b0:5a0:3387:2adb with SMTP id l6-20020a4ab0c6000000b005a033872adbls939882oon.2.-pod-prod-05-us;
 Thu, 04 Apr 2024 06:45:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7ztAPKaW29VDUxk6g7iCRiJML+6fk8jymz0Huf65wRBIl3KdDS7A6nvdYcPx9e0jXe3TBJXtnFGP2NrJzv/TxB1JOQFTLzeJ6Uw==
X-Received: by 2002:a05:6820:2713:b0:5a7:c78a:2c96 with SMTP id db19-20020a056820271300b005a7c78a2c96mr2413528oob.3.1712238355073;
        Thu, 04 Apr 2024 06:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712238354; cv=none;
        d=google.com; s=arc-20160816;
        b=ybQIPk9U6cB7dj7+drdLC3spQXd/k26MssjATgG90em0tS1fXZOzFu8/oPdxm+90up
         N8so8WW67k2NASMYQv/IVvrTZ8+OK7KHWNYazhoIeMaL7FD0SACbW5lNYQZ1OjAggk3+
         W6CKbTEzrx5bv9yadwxZKfrB1j9ccHi0atDhNdpiTgFF2JhTV3ZbuxcDpzA/jFEIevtZ
         xWnmYLot5pAbdpHVuwfcnAc65IdjX2peUm7Zjm+/tCT8JS6IASy/2/D8lY6BTPDLlF7x
         L5FMxNxGDtUCqUBpxy84E5QL9anwqhaJ/JAQoRXkPyl23fo3sGpdA62JVgS88d6hMIxo
         keSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rIJ5gF+bcRTkcUlaZMOl88O4Cd9tIV5iHXQOl87YQrE=;
        fh=zru9GisBudL6wscQvdg0j2VNCYgIpM0w/4ZvPY1SZGc=;
        b=Jto8OIyAFCVpOOuj9YPqpfnRH+jJtBjZbtndeHhTgD8LtWJezQ3AVUFy+Ao1Z290nH
         JYhEFBcH/a7sglqYM/LXgLsue0DAht4HkE3FeQW+xe+e+DxsIfjYaqk9hUZ5uIlXHXNH
         +vltBftak421A2pyv7IoroKuZKjZG5dCRMjEa6xc9ktDDWJuzBiiBTDp9hNfKfAZcGYh
         ny3bsS43ImBIRb7BQMsnoVnBQFbThzE8aB8PIbrShgYK/fZ0QXOFKpAiuUZpASRwtx2T
         zU94Ci23vckNcJM6kFsTNVyLvhwrxxfgNa6RbeeN0n6x2NkMdzv3SySRlVktpR2q5xIw
         610g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DTBdMOng;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id h7-20020a4a5e07000000b005a9cc750089si275436oob.2.2024.04.04.06.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 06:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-256-xFKJxaPUPkGlWmgqta_Asw-1; Thu, 04 Apr 2024 09:45:47 -0400
X-MC-Unique: xFKJxaPUPkGlWmgqta_Asw-1
Received: from smtp.corp.redhat.com (int-mx10.intmail.prod.int.rdu2.redhat.com [10.11.54.10])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 9E69F85A5B7;
	Thu,  4 Apr 2024 13:45:30 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.21])
	by smtp.corp.redhat.com (Postfix) with SMTP id 8942F492BD1;
	Thu,  4 Apr 2024 13:45:27 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Thu,  4 Apr 2024 15:44:05 +0200 (CEST)
Date: Thu, 4 Apr 2024 15:43:57 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
Message-ID: <20240404134357.GA7153@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx>
 <20240403150343.GC31764@redhat.com>
 <87sf02bgez.ffs@tglx>
 <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.10
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DTBdMOng;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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

Perhaps I am totally confused, but.

On 04/04, Dmitry Vyukov wrote:
>
> On Wed, 3 Apr 2024 at 17:43, Thomas Gleixner <tglx@linutronix.de> wrote:
> >
> > > Why distribution_thread() can't simply exit if got_signal != 0 ?
> > >
> > > See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/
> >
> > Indeed. It's too obvious :)
>
> This test models the intended use-case that was the motivation for the change:
> We want to sample execution of a running multi-threaded program, it
> has multiple active threads (that don't exit), since all threads are
> running and consuming CPU,

Yes,

> they all should get a signal eventually.

Well, yes and no.

No, in a sense that the motivation was not to ensure that all threads
get a signal, the motivation was to ensure that cpu_timer_fire() paths
will use the current task as the default target for signal_wake_up/etc.
This is just optimization.

But yes, all should get a signal eventually. And this will happen with
or without the commit bcb7ee79029dca ("posix-timers: Prefer delivery of
signals to the current thread"). Any thread can dequeue a shared signal,
say, on return from interrupt.

Just without that commit this "eventually" means A_LOT_OF_TIME statistically.

> If threads will exit once they get a signal,

just in case, the main thread should not exit ...

> then the test will pass
> even if signal delivery is biased towards a single running thread all
> the time (the previous kernel impl).

See above.

But yes, I agree, if thread exits once it get a signal, then A_LOT_OF_TIME
will be significantly decreased. But again, this is just statistical issue,
I do not see how can we test the commit bcb7ee79029dca reliably.

OTOH. If the threads do not exit after they get signal, then _in theory_
nothing can guarantee that this test-case will ever complete even with
that commit. It is possible that one of the threads will "never" have a
chance to run cpu_timer_fire().

In short, I leave this to you and Thomas. I have no idea how to write a
"good" test for that commit.

Well... perhaps the main thread should just sleep in pause(), and
distribution_handler() should check that gettid() != getpid() ?
Something like this maybe... We need to ensure that the main thread
enters pause before timer_settime().

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240404134357.GA7153%40redhat.com.
