Return-Path: <kasan-dev+bncBCKMR55PYIGBBF6IWOXAMGQER7CSFNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E692854D8D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 17:02:32 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-411dca63c56sf5124295e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 08:02:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707926552; cv=pass;
        d=google.com; s=arc-20160816;
        b=CXJXVet+I7wWTTN36MgDamSklYx4wBmvj1aQ6KZJwu9ghqdulHMRxOOVMj0OrnfUft
         /PvtMMhConIHnZSV2ImZ9gcGf5D2f5d9lFIXfr8THKYcm63CO5HZFUjuR8k5+7SefVql
         F1SBwkfUSMOjOOTdJFqPelBwzsyBbnHr1x8KsoAmbP4+WhOGLqTaMqjAskYtZQRfBRXg
         8ffHX4WPs/5nddtR94DMqagPRKWxkCvVzSdjzeqeDs8xOTlevQF50xwdnQJeIxAs8MXr
         aKILclTlToNou0ErPnKFcKyKRRvWo0fT5MDrOIrRMygMHXs/FW/pGRfHjTw6p1Cib20L
         WVtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vOWYVM/icmLiQAZLJugwjkanbGk7Va1OZYuMq86jOkQ=;
        fh=1GYO27pZHwCiguwbk0d0SHqzJO8FA18ZyMyS31iarKA=;
        b=e00wa2f8Lqt7APJGkCjd0ji2aOecwxt0MyF+iaisz1louV2/3fIBVFf9GE4SeRz5QO
         9zUOqM7dDLYh+2R1+W1Y8ubScefORrPFR8F6TWFUyDQ8RqVHOdZMBqDErnm6aYoKzlyz
         d8BgS6/uRqJo/QvXAZLLeVbjYqJu4m3MssTahj6xbX4mj5TEQHy3UKLBqJ8hI/1eKUYQ
         xUiCbXNVRL5NJGUGtbkTftI1ClZhySD6F2vAYiMf+k69M01a2VPlx5vwdXqKkCWTpQBX
         PJKZBKUzFRkmu7NU/Dww4y4cKhr+TcZa4nlNr5koVdo4BceaZpuGT+UiapsSOoG6BzOu
         lNeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pWIk5zuX;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=rrdpvnmv;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707926552; x=1708531352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vOWYVM/icmLiQAZLJugwjkanbGk7Va1OZYuMq86jOkQ=;
        b=FmB2vX+FOjWAh8HaS07uzfYfI45EJy58pp7uzb44ir3lZuPkZeOjuUmsMCBbn5SlCk
         xTHzkZ6X3OxI9ilmf8nBQvaS3/ugnW8pFhVeHFD+9K8nPKjooTijblm5etq/F+P1gITG
         a6W0hM9zGBfwWHTuWcGUWRRWTHTt36IO5xIwiSehufiNEazaseX4g4AxybvCqw6D1a9n
         kAQRgPKt/jv9SP7TEk+CXZKqBVkCWPJKtzou92z8QMvJMhF+wM0QCTmYFY9UR2au1by7
         vmXe2WMs69EqMehwAgJbcigN8LYnLP5GgkSKhpb/P+ftzZyOVe0xsYfAtzYLV2Cla+F6
         vSZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707926552; x=1708531352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vOWYVM/icmLiQAZLJugwjkanbGk7Va1OZYuMq86jOkQ=;
        b=wqPakIdax9BMRlYZLyCQ+82tlLNirogAnlurjLf9xmW151K7778jjq1pXR3a50N/AB
         TcYgJwUy4cM/m8TC1qVFVQ9UTB6qFtUp/yVAcHVEgFA3CaYFjwlXzo4yJUJL1luaQq6a
         xFOfpBZ0YJq0rnBVHJISjSmSTcPcgg7srCWWjVcG0uBzUeiKMsdAnaq/a/fVPt1WTPWE
         NrVry/nItcd2UYNyOKvShyNCrnSCH8306ViEG2HgXdyct01wiCnDhklZrA9nj0q2FE7V
         Zsx5hUdMHQ5CBL8npTJVdgwqA+ivyP7/3bAKstsxC7PLwzwiuyxW4MKSLNX1Nemq4Ifc
         lNEA==
X-Forwarded-Encrypted: i=2; AJvYcCVjeFBVYJDKzWo4CZxVf8gO6MzPAeOfg3C/AfuPb4PAAxmTmFAPP3fp0DGLMPXBKnaO1xnWJkPW+cwiPDxgYiuJlKPGrD/jiQ==
X-Gm-Message-State: AOJu0YwAfRx+ldqDVDOgLee2vNvjOxPkr4xNSMeJOJNM+osqvR9lSDYE
	ug+i6S/FlY0sf8PzS9O+SvX7HBK+66qPMwW72qBVhQ26o/jqxPcA
X-Google-Smtp-Source: AGHT+IGmBO4Og3eEtYKPsPhQKP2sKOC/TuXAgpc3y45EFgI+dx+fPd2oI/vqdIksKZaG6+VrI3xRfg==
X-Received: by 2002:a05:600c:3545:b0:411:e167:364d with SMTP id i5-20020a05600c354500b00411e167364dmr1972394wmq.30.1707926551376;
        Wed, 14 Feb 2024 08:02:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e0b:b0:411:f09e:9d69 with SMTP id
 ay11-20020a05600c1e0b00b00411f09e9d69ls330496wmb.2.-pod-prod-04-eu; Wed, 14
 Feb 2024 08:02:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhE8zZYMzOR0RZ9dqkl6SnrBRY9q2zy3vxCXy4qtWl+d3uaB4MH4jW7SwT0REJe849nTBr2gpd3LyYdLIgWXfIJf+jZti/zBJd0w==
X-Received: by 2002:a05:600c:3f90:b0:411:e634:8377 with SMTP id fs16-20020a05600c3f9000b00411e6348377mr1739650wmb.38.1707926549460;
        Wed, 14 Feb 2024 08:02:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707926549; cv=none;
        d=google.com; s=arc-20160816;
        b=M7B3thtWGL3603Z9yzIYdwFsemMtoexsBhLyR3epsWqbEkImZdA2w5ktLwTza4BidH
         VzJXgO9RF16V4jwSKMfuVFF7pHGcGSzXjp1duUuvi08PEQhSui46feZ3DmAkxo4N7rzF
         RHQrZAaaqyhlRX3fo61oCLVqXe0c0AKKaqaQy3a1mW8F/RMGCMzo+jXOkxa86aGD7ksg
         6Y0U+H1Bf3EKQzvEbl0+9BhzB42xLQtC/nONKudoiBYSjpT9js9iySNIl+pXAtLuwZSU
         5/ycKtym4rG0nq1PxW2YzKKEDV8Xm5EuiG/ZZLIE7iZlv4E9pyr/g1Cpk5wOP7HxJmLc
         PLBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=pPXp/+cRrehfUHk2IR8IXdxKLmNDOpV5ikCDlFNmYEA=;
        fh=DFZ1Vji/bo41e+NLTIr9JGehrS1bKYlcgt0V3A+pp8M=;
        b=mmPzqavr4YGXgE1v1bxFcOSg4sF9Nd/139kd2OVZ3JprGdRM0RYIaAkWM8MFK39y36
         98bWW7TYGor8HU5oyB76lUztO42IYTbA09nlnoVJpqBj5cq0knOe1yZDLeMy7NjQjLJp
         wEyO/KPtIFY6EOVYOJScsf3j+TJyZPl4gIhl3f8Dw9Niszt+hfn5e0iHpzzDdYgqR4zj
         QYbNALforac2ZRB/FyGxW7QrC8A39cOgfDaq47VTAMOevNlggPNZKbH6pyaYs398LGSh
         QjeJtN4tw41QGvl/XKLQ21nL4WufWk6hvOeHSFgft2jjTW5VZpY9QK0J1svfi9DL4S5P
         zM/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pWIk5zuX;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=rrdpvnmv;
       spf=pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Forwarded-Encrypted: i=1; AJvYcCXt7t2lCfhAknKrzuTwl5ijm8K0TeEt+bRRCucIG5sBTDrTHlxQQZvYzuegduiuawQTfedJrk2lE31FURxWc77rFJ7+p70zWMeiFg==
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b00411ae8e5948si72777wmq.2.2024.02.14.08.02.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 08:02:29 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CB6651F810;
	Wed, 14 Feb 2024 16:02:28 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A66B913A72;
	Wed, 14 Feb 2024 16:02:28 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id BzUCKBTkzGW2MAAAD6G6ig
	(envelope-from <mhocko@suse.com>); Wed, 14 Feb 2024 16:02:28 +0000
Date: Wed, 14 Feb 2024 17:02:28 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Johannes Weiner <hannes@cmpxchg.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <ZczkFH1dxUmx6TM3@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240214062020.GA989328@cmpxchg.org>
 <ZczSSZOWMlqfvDg8@tiehlicka>
 <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
X-Spamd-Result: default: False [0.19 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.com:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.00)[36.61%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[cmpxchg.org,google.com,linux-foundation.org,suse.cz,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 0.19
X-Rspamd-Queue-Id: CB6651F810
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Bar: /
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=pWIk5zuX;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=rrdpvnmv;       spf=pass
 (google.com: domain of mhocko@suse.com designates 195.135.223.131 as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Wed 14-02-24 10:01:14, Kent Overstreet wrote:
> On Wed, Feb 14, 2024 at 03:46:33PM +0100, Michal Hocko wrote:
> > On Wed 14-02-24 01:20:20, Johannes Weiner wrote:
> > [...]
> > > I agree we should discuss how the annotations are implemented on a
> > > technical basis, but my take is that we need something like this.
> > 
> > I do not think there is any disagreement on usefulness of a better
> > memory allocation tracking. At least for me the primary problem is the
> > implementation. At LFSMM last year we have heard that existing tracing
> > infrastructure hasn't really been explored much. Cover letter doesn't
> > really talk much about those alternatives so it is really hard to
> > evaluate whether the proposed solution is indeed our best way to
> > approach this.
> 
> Michal, we covered this before.

It is a good practice to summarize previous discussions in the cover
letter. Especially when there are different approaches discussed over a
longer time period or when the topic is controversial.

I do not see anything like that here. Neither for the existing tracing
infrastructure, page owner nor performance concerns discussed before
etc. Look, I do not want to nit pick or insist on formalisms but having
those data points layed out would make any further discussion much more
smooth.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZczkFH1dxUmx6TM3%40tiehlicka.
