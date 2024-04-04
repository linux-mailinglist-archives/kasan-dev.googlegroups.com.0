Return-Path: <kasan-dev+bncBD66N3MZ6ALRB74MXOYAMGQE7J6RYPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id DC528898B0F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 17:25:53 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1e229cbefe7sf1901215ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 08:25:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712244352; cv=pass;
        d=google.com; s=arc-20160816;
        b=GqjDL5tir+ScRBip7lORwETK4ustuD2mcvCMERRAgz5x3ObPPDMId6isMqbeROhk6w
         PGcvRSNcycnS/b24b7J2JfKfaSl9NUY/1rHLZLOQR0YhTjm2yWhuulOF6Jx8M6IZMO7K
         aW6jjFydYkvAjMIvYl3tU0s5SIw3zqV9/8CejBzspVdKKLYQtnOyVJ77ddZZlmVPmiX0
         jwaIg50I9jr1fraPXyiFsE+R/dGNiP7zeAxjYTvHTO+TnJ0xGgFfFU67WLpeWbb0QMyh
         DfcrwEYCeoJPRXIh13ivQfhNDIHo9l4PAKtFMtDFjFpCFtaE/f9YS20nmr5AEQOSmcEC
         0SsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=iMh8Qh3Qi6Lcv1QubuYuIut/QU4m3TQFcdNoOaKYAJg=;
        fh=aWRxV7n4wP4q7eLTKrS+KYidz7BZMmO3fXhEWChjtHc=;
        b=y+IyR/2bX8HbFdkVJPa+QYGiyJbM2N5FDYUqa/ay1tQ99wQq+IhM4LG0RjLDipHZ5B
         V/NPd1N0+XDuTwcCoY8sXSObeR9jCT0YtLiOGq930YCQOustYLOPMYKPoFcF04B64KUG
         kTf/VhIrHgFh3y69CpQl4fme29SjF4HCY92ZYbmrxi9aS263QsYNxIsswCqO3V+WFri9
         o+CGBJWmI8hAxOE8GTUfgwMXxZGsBhGhkHa/xsWpqSbCjVgCLtXv0hI9s/WA+/MizILz
         MQ4ZH/HRaEzEftMxkMyExkiSW4VGNO1vOSVV5xCYe0gAoFo7QBEEtAKqRrSoLOrA14rS
         Zi4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HDIwCxM1;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712244352; x=1712849152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iMh8Qh3Qi6Lcv1QubuYuIut/QU4m3TQFcdNoOaKYAJg=;
        b=t2uE5E9ECrnUmRRBMKUHy5hYHy6Y/zuj+k4A4xN/1/FUEJ75YP0okdqXbPToJn+3aK
         RPUY//3jEj6fIpUB2GZjERzMA0+gFgFyDT1Zt6NyjXmAKbg1cXrHHTSDrmi3NjjoSinL
         TF2DDtmbwwh0mX7nvNQ2UN9p89deyqPxXEP1NCBFVOt+0X/AmiNRUqGL9E/Enl2A+/B8
         o5K1ckaJSQjpx2g+9AuMaMNQTrFOtPp+t9MryYDfoBZ4D2Mk/kw0XJdocj8KBF8KRIsj
         14uBwCGEzGf7ZW2C1qJKP4Bw4ZjKXdmpDqYjyiN3969gSqUgubSaDCZIrxg6KYSjPal5
         CCMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712244352; x=1712849152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=iMh8Qh3Qi6Lcv1QubuYuIut/QU4m3TQFcdNoOaKYAJg=;
        b=cVDTBtTIsSqutzqozQt8Fa5SgZw/eMPYNMJX/aqeuqVfjvIK5wJeHA97/E9hiaIRQ2
         ld3twmwJCWykRlzb6KzkaNYj7ckKBD4MG4hjM55CCo9modEYnhjiMk8ZvKJRC4YJN0VT
         QW7TQpGsJaO5W7/Dgxq9L3+0sx3h6yAphFH7FeWPjCA1rMiLs1n5FHEX/oja7SbfoT73
         pTxY3sFlDiXjWRo8ss90AJr2UmuuOIpQ3AmUE6TMrjKF73Brlx6xmakNldc+GUik9eG/
         p9kwSM6mEk/b8OKCwjn8P3+BrnOWCI37cCLGAcOTJNszb1deS9B7KCvV9Vd0F8teLXe+
         rHDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWBk7w8Jj3KTlgSR6c65+r/T4TvdG2FFZ54xdTlHPb73z8I8MLGc/HphsMU03MgaZmqRt2HzkCo9LqGjh5ghVx54TaLVz+0g==
X-Gm-Message-State: AOJu0Yxqawz8H0ivf5I6JZN63VSB0JOO1A6neLIh7b/JPnVjwaAvuOG/
	Y7GBtRZoVFWbfN7kNR9I8xHH+27cU8QcErq5MVKbHkEEbXM700sg
X-Google-Smtp-Source: AGHT+IEkeBB8x91wLykvnww3uN4KyO7ytGJ/4MH4EHR7T2whuHjR31pLH5ozopvVJ4tF6q1iubMqOQ==
X-Received: by 2002:a17:903:2292:b0:1e0:b5d3:3f95 with SMTP id b18-20020a170903229200b001e0b5d33f95mr108254plh.19.1712244352258;
        Thu, 04 Apr 2024 08:25:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba93:b0:2a2:4332:ab0a with SMTP id
 t19-20020a17090aba9300b002a24332ab0als585425pjr.1.-pod-prod-08-us; Thu, 04
 Apr 2024 08:25:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtli72t+Y7GibdUc/Vi4M2zODgQK45PQZtE8Jy7lLNHKOdYGITHX+hgoBNHDRATctzAP9aFkmhy2qio5ooVP7f6VJe3XA/TAaN2g==
X-Received: by 2002:a17:90a:e150:b0:2a2:f35f:f13c with SMTP id ez16-20020a17090ae15000b002a2f35ff13cmr904920pjb.46.1712244350816;
        Thu, 04 Apr 2024 08:25:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712244350; cv=none;
        d=google.com; s=arc-20160816;
        b=mYkj78tdGYxBfIOFXyoHIuVwWID7swI+jCRLz+6lrVohFlAa/wTQiwHP5vQRRDmjuE
         u12wmSD8ANwOeE8mJdKNzOR4igQZotHHP+GnHK3Ufl0+iPHQW0A7J356h5O0Vb5ZAxWM
         2SgqHdy19NuzanKWm7/hEQoa4EZncLTzIiRb1yzq3S5e0YBzpC7fKUfzwcZ1EGtYBRvX
         tL2vl5dVyejw8xi3rj6r8DQHs9xN1NZxdj/QxxjQo3SxRmCVwc+Sk07J4cAKEc1JzgQM
         uBBx/Kghj3Jrilj8iGNv4wUI4lKcUHrYfcH/tzQdc4xisOCJZEAChiq6L2OXdFXugeIc
         g9aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EyANxchTUq4vCZ8B0GlMj1ALpGGfgcRd78F9nkanEmk=;
        fh=ct+SAC++KuMnHEs0TDY7BoMNklHQXTXWPHBS4yDpdlg=;
        b=nVV9tYrdLxDBYP1vPY6JZt3vmy+2qA9bdv+JPgKLRC648TC+AOdxEf0yNenpaoA9XX
         FLLsZa96ju0q9F1zH4Vke3upQMCt7oDxYqw6nlTpO/c4M2D4XiaJ6c9pDKAAxeGF9o+v
         bW5wfoYhh0DlX/xloUAzjdrBT3NPr94Tge91D8zgxWz1QPannx0SLoYMNxJ6uUNp6cDq
         BEf7hCW6Wq2TVgm7Y4h84DALsgBntiJhF15eW8A/AeauUNL9H/jCe5mC/xxjRuGlBzEi
         rJfaePsh/moWhDqyGgSep6Z1E1pHSj7G8XQHa+J9GpJwG7f94WDo93T9hIWSDswQqqmz
         ssyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HDIwCxM1;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id nu1-20020a17090b1b0100b002a290bec184si99058pjb.2.2024.04.04.08.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 08:25:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-694-tUm63H4bOu2bbGcK_ijisg-1; Thu, 04 Apr 2024 11:25:46 -0400
X-MC-Unique: tUm63H4bOu2bbGcK_ijisg-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.rdu2.redhat.com [10.11.54.2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id CE27680C76B;
	Thu,  4 Apr 2024 15:25:45 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.21])
	by smtp.corp.redhat.com (Postfix) with SMTP id BAF1D40735E2;
	Thu,  4 Apr 2024 15:25:42 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Thu,  4 Apr 2024 17:24:20 +0200 (CEST)
Date: Thu, 4 Apr 2024 17:23:57 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, John Stultz <jstultz@google.com>,
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
Message-ID: <20240404152356.GE7153@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx>
 <20240403150343.GC31764@redhat.com>
 <87sf02bgez.ffs@tglx>
 <CACT4Y+a-kdkAjmACJuDzrhmUPmv9uMpYOg6LLVviMQn=+9JRgA@mail.gmail.com>
 <20240404134357.GA7153@redhat.com>
 <87v84x9nad.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87v84x9nad.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.2
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HDIwCxM1;
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

On 04/04, Thomas Gleixner wrote:
>
> On Thu, Apr 04 2024 at 15:43, Oleg Nesterov wrote:
>
> > And this will happen with
> > or without the commit bcb7ee79029dca ("posix-timers: Prefer delivery of
> > signals to the current thread"). Any thread can dequeue a shared signal,
> > say, on return from interrupt.
> >
> > Just without that commit this "eventually" means A_LOT_OF_TIME
> > statistically.
>
> bcb7ee79029dca only directs the wakeup to current, but the signal is
> still queued in the process wide shared pending list. So the thread
> which sees sigpending() first will grab and deliver it to itself.

This is what I tried to say above.

> What we can actually test is the avoidance of waking up the main thread
> by doing the following in the main thread:

Hmm... I think it can be even simpler,

> I'm testing a modification which implements something like the above and
> the success condition is that the main thread does not return early from
> nanosleep() and has no signal accounted. It survived 2000 iterations by
> now.

Yes, but please see a trivial test-case I sent you few minutes ago.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240404152356.GE7153%40redhat.com.
