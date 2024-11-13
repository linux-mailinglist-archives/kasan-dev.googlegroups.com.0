Return-Path: <kasan-dev+bncBCKLNNXAXYFBBL7K2K4QMGQEDH6VUNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 353C09C7357
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2024 15:18:25 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5cf735604aesf94854a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Nov 2024 06:18:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731507504; cv=pass;
        d=google.com; s=arc-20240605;
        b=XDLe7VVi4/mKI2YTTp6E/KI0HrcnufOe2OhatYYF80EPdtk8afBLRpWo8v1yQDNl4h
         biLnaLh24V0uLEFF7RDv4TC5Ky8yfysAyAoPaM4zvEdGgu+xZKgEiebvTFJdLlM6gpcZ
         GsD0Sud9lfgRa9d98MBSql5RfYNit2V/aTY0pZlyaFLz01c0XZjktLQKriakULb8OQ+a
         5vQ4vDE5v3XTF9eNwWZHB1En9y5hXMUd/aMU5TFlaCAdEsMcVo2224BPuAfjVmEkrZeu
         Hmcqh4xqFWYy+GYfxYXdmsBwLjU0iXh+it8dFo+rjsaEtDVLa2Uk1PNBf5QR+rTXhnaP
         rUPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N4bqOORn4Xrq+C72HgBnIM8CSUp8b6VTwg/PmHajN7s=;
        fh=ufBhTq2n+45tnWtiWVVyE85/Ad75eJ6baccoG4Z2kMk=;
        b=aiA2g5veeOa8oUCLXCwLyA1PTTe2ngO+Yo5ezmPznmjFmum72OZ0mPlR45s5MobGui
         AYVzPwn/xl/9/LRiEOOsJ7wPOI+XqW96edKrL7BfoIIWC1KMRZsVKrJ68MX61QKDwtM1
         uwnm4hCnYCB+wSTNsemKWnsyW58N9bBf8abvCsqu3oWpzx0RnWxLzlyXYIcb9FnirN+M
         nZbaaDKSix2q0p6oByy2vL4ZTxe/K7oSN/Mpm3zaVMUifV+NbjhK6RndZK+NvUO2afK9
         qzVWgjDLijPWT3lomZx916WAUJGFwzQ5Blz1LkLxsphBK5TquKLx+EGkcf/KcrwLq0DZ
         P5rQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Qg4YBcGY;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731507504; x=1732112304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N4bqOORn4Xrq+C72HgBnIM8CSUp8b6VTwg/PmHajN7s=;
        b=UnmgKXyZdCIsWg+Ym1C47wrJOiuiypK6VGBNEwCp66E+eQ7LaqAqPIIBxbvZRWiwe8
         pSwLA+aWHONi60C/N8OfQK0xNpgw/bT9ZBma85O99S3pxec3Oxl2aqTxEOuBXbxzcgXW
         0al+uElBGmSA5SDsGl3CrRfAALAp586O9eAvtiYHERDa7po5yppnPoyoeFpRxNiWKaMt
         SlzQF84CB59Ii5wU3Qz03qUkrKZwnKqwFS8JXrVRP6NC4j5efViaaQLfW5zYqGtpq7Mv
         v3rOVgicC/+ZhA4ICIC2xlHbAZFZZg696yHQwwvXZIOEal8SthX6q+XoRpy/kVYXOdfQ
         vPcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731507504; x=1732112304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N4bqOORn4Xrq+C72HgBnIM8CSUp8b6VTwg/PmHajN7s=;
        b=IQqQRNN5+gMhae62o9am8Izz+thaY8UyXVE/3OrUOqL7NngeLvNuiCxfUFMZgqujzC
         mtFbloLmBEH+FvjcTAHtFm6YKq/0/o2bktSZWLB+I736y0cAPIFA22sO8nE7XW8T2B2Y
         SfGTQKi4CPt03HvTDUNhyB1Hq9DqX9FlbJ3IIsYsKEiKMvRVhJ7kYDupJoLwvAIfSDSX
         1AT3ahhUFI0rbqLp5e0kC7WfzCUtwO6dSWZ8oWdi6ESV3CDMgg72KWeZtwbQGcliC+AX
         ibzOAdbXiRfwSo7jFRbKQgiKtOZeQv9nO9NwA1Rw/1NcKz4+pOObtp6qFFrCD+rjZ6vZ
         aj7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlvO3TGXEgpbjdNc2VX5oRnzkYf12sIpLZZ30xhpgWfIuHC3c3ZaqOvgr/WVuiiYoU4qF0Pw==@lfdr.de
X-Gm-Message-State: AOJu0YzjJ9RdbR//wOVRgO4HhE6j4WJxI+I+Kx8nvIuSFuPDzOvNIi48
	Rfo0qC3YPQKC1388VGogChgeM1E35CHOxz6EOlEqEY++0OmO/Dsu
X-Google-Smtp-Source: AGHT+IFEBA4U4JhfuK8il2yQIQDbU5vIW+VewX3d+6lCeaDdDt/C/7p23W23ykedoQia6Dfk8HGX8w==
X-Received: by 2002:a05:6402:51c7:b0:5c8:9615:3e32 with SMTP id 4fb4d7f45d1cf-5cf630cc389mr2700640a12.18.1731507503940;
        Wed, 13 Nov 2024 06:18:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c0ca:0:b0:5ce:aed7:a6e with SMTP id 4fb4d7f45d1cf-5cf7265d9cfls157212a12.2.-pod-prod-03-eu;
 Wed, 13 Nov 2024 06:18:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVJ6tUGaOGDisoY6etZlZ0Jezt7sIJQyMuweY++hlkDJeJjXbhThwMD8jNSo35jUxB19waxyJmHXM=@googlegroups.com
X-Received: by 2002:a17:907:e92:b0:a9e:85f8:2a6b with SMTP id a640c23a62f3a-aa1f807ef38mr297249466b.35.1731507500686;
        Wed, 13 Nov 2024 06:18:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731507500; cv=none;
        d=google.com; s=arc-20240605;
        b=CdJGA2b9dHm5QR0IAN7Yn0JBAtRNWy7g2ogxrnZEZtoyQGBiNXAfrAjz1RpWaWN7Uh
         Bb2DV2cV/+tQjCOCmAV3iegVqxesRlT4PsCU7WFV5TwX4Zga90jh2GMqz4ydswDztgAS
         C4v2pdnKpet7qNmf0GnhtVo+s1sVghHRZjuk8DXuOhWfgr06ddIUxgoVecq1X/HAczbl
         zhqzsFPfrhdiXJODlkjtdlae/syVzXLJdNqDZr+GGMozP72lEsITC8Go93eAQa1HzR+8
         RTByMcIiNLF9za/YtXUz6ganGgjWRbs1JbLONTF/D+V+0xKWx18W/2mUCUO6DdedVfm6
         hTuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=k1NnsfkLq2HnmImLt4DvLhPon1Pe+zCIYBq+XyGR0FY=;
        fh=wL9tgiksU21LQuUjENUoL3ZuEsOd0eKO+dMU1Tg5jGI=;
        b=eKuop1xjvDgViOwh7icUWHaAAm4XH5WE9wIBR7AkbK4s2DtV9PGyT2kqUDenecjCWo
         9ARVbNop+qx7sH+nSJIYaiHKRQ4ZpRmMYFyFJdfP4eeb6MdGyQBq5G+VEkNXSgD7hekh
         /wR4cdqaNJV4mP5IHDdzGyAvzp8k/pZ0bkynqG2lZ7iVeqUZzeIB9q3wMfW47scf/9UM
         ONtN5O8JYDC0pAuVU328eyM+ry10Kvsjfx98fE27j8HbQDxybz9hcUb5+8HC6hqd1JGU
         820eyY6NsqP6/9mH5kvsFhO5s5fQuCip+Pyjk7vfmsXBVEYWfvLITqFtxUE6t+XNPH1z
         HIbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Qg4YBcGY;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9ee06a7523si30261866b.0.2024.11.13.06.18.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Nov 2024 06:18:20 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Wed, 13 Nov 2024 15:18:18 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
Message-ID: <20241113141818.eQfGt53n@linutronix.de>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <20241104114726.GD24862@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241104114726.GD24862@noisy.programming.kicks-ass.net>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Qg4YBcGY;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as
 permitted sender) smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2024-11-04 12:47:26 [+0100], Peter Zijlstra wrote:
> On Mon, Nov 04, 2024 at 12:45:06PM +0100, Peter Zijlstra wrote:
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 6310a180278b..ac9f6682bb2f 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -521,12 +521,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
> >  			sizeof(struct kasan_free_meta) : 0);
> >  }
> >  
> > -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
> > +void kasan_record_aux_stack(void *addr)
> >  {
> >  	struct slab *slab = kasan_addr_to_slab(addr);
> >  	struct kmem_cache *cache;
> >  	struct kasan_alloc_meta *alloc_meta;
> > -	void *object;
> > +	void *object
> 
> Clearly I'm still struggling to type ... *sigh*

Should I put all this in a patch or is already been done?

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241113141818.eQfGt53n%40linutronix.de.
