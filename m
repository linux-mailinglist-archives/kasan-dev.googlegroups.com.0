Return-Path: <kasan-dev+bncBCCMH5WKTMGRBKOZ6SOQMGQERQOIV4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A095B663C7A
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 10:15:22 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id s26-20020a5e981a000000b007045ace9e1csf361067ioj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 01:15:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673342121; cv=pass;
        d=google.com; s=arc-20160816;
        b=qcDlympfPvh9LdOi5v5JlWrVFxFGUewcJcey/BaqV8BY13p4ekXSIO9exS6EAqOIO2
         B8ml82ASJK2giM5GF3n/IXLvlxAeule1VO7B/f6KpDbKh0IPQ8/NUx0v6qE3N0G14+On
         RIjqXnFG4Nq+byB3c/3vOz/yM66voe8/+/kboc2hDb4LhoxzlBeEheF6K5lPRklOJD15
         4Azcf+Goqp/+mzbPARfGsRc3UNOH+OrQzvOWJ7ijYN/uE14hfKRT4XpGeHxg+rW015rs
         OXBdnFoXk4vJrhHjI2f9CZyERN3BMbwT0kO2TfyFNEmuH9JxCLLLS7z7DLDZudfruAdg
         fxKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L4YxPPXfKJRLa7HL/X+PxoMcgePN/dMMvr6uOb1PknA=;
        b=bGKV5izPpBd3MzV77GbJa8QOUORxjLXcqJGIexH+0wQSFq52b4EbKmJaBa0dS6+BE4
         yiqvEbLnDKmz+BfteP/nK3KkVLTWqo5Xfe3R+kIKjLBRTy1OotBREcqV7iS5P3XM2ojU
         6KDTR5qBBYXciZb82TV8atOlO/ppIurBqPCarrSqFOTGigCjDPakKSvZdbwVowF6tZXq
         BqpqoeHgtouKQguONjw2e8b/+XfatzoTBvfGjeLuyYyzhUlgCgJEvmAjOLEhsTFgEpMY
         raa+4Pc94xeVjGKoFkPlnY8/J2vbNq58oIBbTZxDUStPMz6kTOPxwjB+FgnD6Sld2WYV
         BaRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G4FXz9pl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L4YxPPXfKJRLa7HL/X+PxoMcgePN/dMMvr6uOb1PknA=;
        b=hpP7FNZ9iwo0b84MPE4/Qc7wz1c1Wa01/3jTosz0f7APs8ZVxIOpzsM+Up/pH0cH5Q
         X/4d0eho0ZDjwfWSGPHETl/Kpthr+D5qPQk6lZfJN6HsVYZajUg/vIuELwVZbUr2jFSu
         gxwGdB+X3yZobbizJdlXFKWzCLEpQkBgDU3AFqG5Z5Yo3mqRoIDLUeImA2qBwr+bOq/a
         Pvk9i2PafFC1Lz8ZkXn/QKYJKa7bN5186w+avF7CnE09vHvXvW+FAFH6sQvM+e3MznLT
         Tv8Pd4H+yPMcMNI8n4jFEtbPuOvRshhkHnkV8GIc/KQfXmtpHISiMNWdbP9Y/bEaLpjb
         IHKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=L4YxPPXfKJRLa7HL/X+PxoMcgePN/dMMvr6uOb1PknA=;
        b=QXBdvcUq2eE/+whutq/dEiQya9yjJcK/x0aqr1WoW7pvHrJf1UONMIpyWclY01GErm
         Piqt3wpoDuGtBGZMBAgL4ohUERXfOtK3Hye3Lw+QYyPbV/EUYMhmbOOXlEmWN1n71IOP
         d3eLYKXTi7bA97mB2qSAAU+7NBAGp2h0uuRMhzA4qFdW2L0756mzI+b18XqymibL3pi9
         DDaBarq2uYSC5eKX2Wfn8INVK6d7yrttyqJ/kuS/1QeFKC0iU7012fQp3gzEyNdsm03P
         KydJZ5TN81BdXkTzPZ4Pyn8L35bP84bHWwlV07aSuKNvHJ/F069VWLpt9saDPmbxiOsH
         wrGQ==
X-Gm-Message-State: AFqh2krBdXZkEzIjP25+noZ3TaolDvYkurbh2ZE5/h+hOE8c8OXZ7q/H
	JiT5bu2Myg2jLDTQZ/8kzKE=
X-Google-Smtp-Source: AMrXdXuszcF0L34voi1tDBd7gpz1OIlEUwUer+VdDi42fBiD7wsh6tNizPZY12ToX53uR0SVdS1PmQ==
X-Received: by 2002:a6b:d118:0:b0:6ea:a115:5ca4 with SMTP id l24-20020a6bd118000000b006eaa1155ca4mr5198739iob.168.1673342121490;
        Tue, 10 Jan 2023 01:15:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1114:b0:30c:3a08:da82 with SMTP id
 u20-20020a056e02111400b0030c3a08da82ls2309229ilk.6.-pod-prod-gmail; Tue, 10
 Jan 2023 01:15:21 -0800 (PST)
X-Received: by 2002:a92:d3c7:0:b0:30b:eca9:5601 with SMTP id c7-20020a92d3c7000000b0030beca95601mr43661840ilh.10.1673342121053;
        Tue, 10 Jan 2023 01:15:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673342121; cv=none;
        d=google.com; s=arc-20160816;
        b=NNTEb+R/OEh0EXrkDY1vbCxjpzRPVRIAf4akY61OF1cDlIUooDJIMLNKfYzlntd+JV
         zeuxrVZywF1ti2CAEggD7uSIBWOd5Az1sRbHBTebmgMTYsuypPZeBjGxMQIPZzWbW4ZT
         R9kB3Wd0NWStXtCsgH2IUIedeM+0WsjRyzMLlpwPyek7qqij5Ekii9V3gTeSDnLk51oa
         VSO7M9tLrBnNzQpqqROmwlzCskOf4tIBQb9uXjd2LYzKbgJfaRQAkmAoxI3o1IIxU//g
         vBa4/wjN2pKKxiedF8gO6NCJx3zKQkf0XAYuV9UoHUcgii91sYZFKXo6ojBqP8asDM+M
         NaSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BZjVbZGCjv7A5kNPkNeLdv+wkjoamsJDXs8YegeL2T4=;
        b=Zz0DTYSEnA9++MN9oq6nzLTsjw8uAja5kZmMHnhyI+ZcSbgZ+ftp8nZXdC5mFddpam
         GixVXZTby383mcwskiTB0R5aa+FjSAsdyyQJHk85jQXRdEpeJGQDtopzEC8PYHZRJIJG
         z9HZM+AaPhkSfW8u7lCAuxiQCs2fuSg+6SEA9FowxocwhdBmUfJd8mhDzvkgZyNlKXyN
         uU3WSCjaJRU15/K9oxuE4srzKfMONHJYmr5Q+KunLVWJiwXCiUjkR1USIj0JsGPfg7l6
         nNfos0MNQrGCxPYW28EtqN0BUDvlLSVrbhWvR/1cswYxN+mclDc7WCUxefgvCB6Fc8QT
         YXBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=G4FXz9pl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id g12-20020a02cd0c000000b0038a5b827993si709039jaq.2.2023.01.10.01.15.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Jan 2023 01:15:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-4a263c4ddbaso146958907b3.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 01:15:21 -0800 (PST)
X-Received: by 2002:a0d:f084:0:b0:4c2:51b:796c with SMTP id
 z126-20020a0df084000000b004c2051b796cmr1329440ywe.144.1673342120546; Tue, 10
 Jan 2023 01:15:20 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
 <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
 <Y7z99mf1M5edxV4A@kroah.com> <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com> <CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
In-Reply-To: <CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Jan 2023 10:14:44 +0100
Message-ID: <CAG_fn=W36J9FNtkdFN6Ygua+hZKd3cUg9akJvx6rJknr9T--rA@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Eric Dumazet <edumazet@google.com>, Dan Williams <dan.j.williams@intel.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=G4FXz9pl;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > > Unfortunately, it can not be dynamically enabled because the size of
> > > 'struct page' is unfortunately recorded in the metadata of the device.
> > > Recall this is for supporting platform configurations where the capacity
> > > of the persistent memory exceeds or consumes too much of System RAM.
> > > Consider 4TB of PMEM consumes 64GB of space just for 'struct page'. So,
> > > NVDIMM subsystem has a mode to store that page array in a reservation on
> > > the PMEM device itself.
> >
> > Sorry, I might be missing something, but why cannot we have
> >
> > #ifdef CONFIG_KMSAN
> > #define MAX_STRUCT_PAGE_SIZE 128
> > #else
> > #define MAX_STRUCT_PAGE_SIZE 64
> > #endif
> >
>
> Possibly because this needs to be a fixed size on permanent storage
> (like an inode on a disk file system)
>

Ah, thank you, that makes sense.
Then I'm assuming some contents of struct pages are also stored in the
persistent memory. What happens if sizeof(struct page) stays below
MAX_STRUCT_PAGE_SIZE, but the layout changes?
E.g. doesn't it cause problems if the user enables/disables CONFIG_MEMCG?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW36J9FNtkdFN6Ygua%2BhZKd3cUg9akJvx6rJknr9T--rA%40mail.gmail.com.
