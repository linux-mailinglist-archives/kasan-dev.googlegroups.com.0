Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBDMNRLFAMGQEU2ZPVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 26A23CC7179
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 11:31:43 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-64b482e5f96sf179421a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 02:31:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765967502; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ts5IgP+d5IAawak2lIsvDk7C/yjbbCQk6mfREpe92YTfuWd5iftVDyRYnysF24QW3U
         Vn53Iq+obxtq1xIqWdYPmAYUfMRhFggeap1sOfNp3kxJGQN76R5uJLoNZ0tXIfQnHGdb
         b94x/KzQehWCQQB3ax2yD7b2imohXV+zFu25h4d7GjajrPrTN2p4Wu1MN1VFwRsjdGCf
         zFWDrRVspfJeUu49QIBzmPRZhSqnSe2L9+r2TB+djMYH1qk+g4rH0lmsZZIoZ3nW8OT+
         cdR2M+zJdpVPWFJzCgmqkxD6Q5elGBG+Af7U2lxMF+T5T/y0kLitGvH1cn6Z2kQtf5en
         AmCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=+SrIJb4WSVQnjcsIecqpP/Ys2nwQHLYvoGC9fV5bYDU=;
        fh=aOyymFUsYSiFhd6jOaNThYBJesAHNxXnHQiPyMC+i2Y=;
        b=ILBVQ3qK2AUIpT5uPdKqqGfuEdTgiyxnnZyUA4Xl8V2ZsHCADni5ZRBTNbkLxs6fyu
         EPDQG2+9LsFDT4rjb9CDVA4nrWjy65drY9UpUknJqMDk3Zs8eO9I8OAWMtPpPapFdc6u
         gFP3iqvCzMPHo8p8Wwxa6rxyIw09YyvtZh2GJxOe4PqlkDD+QmzEQf5mL4KCGLqDWELs
         h8kNVmfT6Zk4FhOikf42adMDYBRy52FZXlrupAzTHR5+PnsYBYSAa+Ovva6YTNilJzoN
         MdQ9Nhv4NIvm30+5ctQ/3FswW90Qcp+XhwwnWcvqrnggg4OSH+U/jvaZspxbQm+HcgCd
         +c6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=XuCnJj0D;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765967502; x=1766572302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+SrIJb4WSVQnjcsIecqpP/Ys2nwQHLYvoGC9fV5bYDU=;
        b=IGD3ZnCXSZvG6fuMdKq+LkaYOr4WmPjMwPjjQqaZHtVJ8XfIlL3cf0wAm3ZF50ZqdI
         z2N35uhdJ6t/KfAkATP3+MU/W3gh3gENqhSE042SQwC4RqZMnjDK0VYpn1TNC223dm8a
         lcj/KF6jjNvT6bW6PXe+krJY+8cioBOfF8B+VYtbrSncmY8PcGo62TLxX2mAjt0v095h
         dBSMUMnlW4LA0spO3w1AVJSLGCXIEwbb9+S6WGERWXthEyJtwybSEr4eYt1LOPF57X1W
         Kd9Y3ub7Xr1z2jAXHlzaY5wyOtIQ6h6t+iZrH6t9st2NtTLms+hB3km5FMxISzSa3VrQ
         3jbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765967502; x=1766572302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+SrIJb4WSVQnjcsIecqpP/Ys2nwQHLYvoGC9fV5bYDU=;
        b=QEC1/XKlzgNXBiWPIPTilLZ9mwa5rpEnkhIL8v/AsFIkoveeWXJYSNEGQ9extHfFMg
         UCadQgzIMKpR0PqaHAOP3sDp6GK+rFh75cxUSnBmQgqGkcnxL9U2ivekwcZagWN51E2p
         iPfDPjo/q2WQTqfy/NSLH6tOjZuXrUVUsRf1dAabZSevXm9wfxgyrkjBOqMoFtd52h6c
         44YmNnYwhQ9dHRF36fVC1uFiqD/8O4QsyB3OEE+hBKuniWiVqyeqZTUnv8CCbM/hbYGh
         Na1rzPiybTZINH3jkrzCAKQspU8rQ2ezd7TUJ59afMmsVufv/voTKRVzuLmHCbG1XG9m
         ldAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8RGVCHUZFQTKoamVBJak/DyEiKk1r/BYvYEvFv/xe4ut2CgqDP9Rab7oTh2V/EKAIKxwhEg==@lfdr.de
X-Gm-Message-State: AOJu0YzIT730IjQ0aPTuSsWu/XGFHi+ByXPYbIXa61hp+j9R33VMQ1oW
	Y99kBKdMSrioS/Cac+38fU/i+HPgNBa39IggDTWrZDd2l3FxHC4XaOsw
X-Google-Smtp-Source: AGHT+IFaNSiTeROpsfgr/VD3fMLbi+oPWc5aOjxF+MjJ2AL7EXxwOmt/6wHC2Lt1OL/DMxJ09NWS8w==
X-Received: by 2002:a05:6402:278d:b0:649:aa03:6d7f with SMTP id 4fb4d7f45d1cf-649aa036f24mr14681411a12.23.1765967502243;
        Wed, 17 Dec 2025 02:31:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZXZKnyq2H51cjARAGo85RO/CZ++7DRNhs5ROmg6XtJ/A=="
Received: by 2002:a05:6402:78b:b0:64b:403b:d9ba with SMTP id
 4fb4d7f45d1cf-64b403bdcd9ls621508a12.1.-pod-prod-01-eu; Wed, 17 Dec 2025
 02:31:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWEOPF9p8kgwKab8nPDWL8gmSJq39g+3L1FS0WWHn9Wotu6uOMBy5qGazT+niM+tXqSDHTy8Ji8Skk=@googlegroups.com
X-Received: by 2002:a17:907:2d88:b0:b76:3478:7d52 with SMTP id a640c23a62f3a-b7d238bb0e1mr1954089066b.38.1765967498956;
        Wed, 17 Dec 2025 02:31:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765967498; cv=none;
        d=google.com; s=arc-20240605;
        b=EKlxW3DULkoW2Us02WoXSHfycAJSuRZsGDvYYUP/sMcSha5BzWle2ywowg0JWBdSVU
         vEP1AQCoTEnd1uVQd6ofBy51x8boZaa314oMn6JKDEDODbN3r9/vAhhiFY4eHN5o2lpU
         GP2/WThG0ZRNUcj1jggBjNr+JjcL6Dk/I9TzNS8yeMp0f3bzaIDQLjlZFPjuslE7iSSM
         PxtT1m0BDX3HAouHisylU5SaOH7KbB3WIcKdHCS6GEFWluMDaxb+rNPWj5xaEPm4ZxcT
         bgYzQRMBw9Am8xcJ3MJXy/DHrhr+UT1HNV4Gf0tHusyzYV4vF1wN4rtRee38x8LTUIB8
         d+sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=b1d43wiHNx7VZeptPxlkNjgMo8OMak4wV1yoG3x6lk8=;
        fh=xZjOuVf3IvPLFFOUk85tXHTFcmyHd3j9XTdhyiARvf0=;
        b=C+E8QE+c/TK59DTi0w3oZJWMDnAIpOCduwoSPgzsNTxS5S9jzfo8OXc2e15eU9p7yx
         SXXRw44jizAZQ/XQAyawBIO+tjFqau5iS3TcYbBPEcpGXpPyoqPfKqegNipXjq5om+gz
         T+e+qiKaR67XmUrQpl00HDDagaGnqz9q1jv9L+OHC7p4vpKbCXwCqfVRK65LZEAjF0WK
         MBkV/5pGv+ouITNwHHqLpBXXUFKfZW+7XIfkxBcjsb2h7p+kLX8TIS803nrcMJ1iC2rg
         FqTrvf8tbjvH8H6NUoDoB7rsJKOtjkTQUERqo+RY5H9xMVOOWfYZ++c4rCCjC3y7/Prg
         W1zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=XuCnJj0D;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b7cf9f386d6si23975066b.0.2025.12.17.02.31.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 02:31:38 -0800 (PST)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1vVooa-0000000BlwN-2EFt;
	Wed, 17 Dec 2025 11:31:29 +0100
Message-ID: <9adc2c51cb0b176006c362c26f2b1804a37b48d6.camel@sipsolutions.net>
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Alexander Potapenko <glider@google.com>, David Gow <davidgow@google.com>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Ethan Graham	
 <ethan.w.s.graham@gmail.com>, andreyknvl@gmail.com, andy@kernel.org, 
	andy.shevchenko@gmail.com, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, dhowells@redhat.com, dvyukov@google.com,
 elver@google.com, 	herbert@gondor.apana.org.au, ignat@cloudflare.com,
 jack@suse.cz, jannh@google.com, 	kasan-dev@googlegroups.com,
 kees@kernel.org, kunit-dev@googlegroups.com, 	linux-crypto@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 	lukas@wunner.de,
 rmoar@google.com, shuah@kernel.org, sj@kernel.org, 	tarasmadan@google.com
Date: Wed, 17 Dec 2025 11:31:26 +0100
In-Reply-To: <CAG_fn=WvdKZgmkqa09kwLLH3P_j6GFYzopeD-PZ-Qt0-1KUaGw@mail.gmail.com> (sfid-20251217_111949_169881_DE704F52)
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
	 <cbc99cb2-4415-4757-8808-67bf7926fed4@linuxfoundation.org>
	 <CABVgOSkbV0idRzeMmsUEtDo=U5Tzqc116mt_=jqW-xsToec_wQ@mail.gmail.com>
	 <CAG_fn=WvdKZgmkqa09kwLLH3P_j6GFYzopeD-PZ-Qt0-1KUaGw@mail.gmail.com>
	 (sfid-20251217_111949_169881_DE704F52)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=XuCnJj0D;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
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

On Wed, 2025-12-17 at 11:19 +0100, Alexander Potapenko wrote:
> > > 
> > > As discussed at LPC, the tight tie between one single external user-space
> > > tool isn't something I am in favor of. The reason being, if the userspace
> > > app disappears all this kernel code stays with no way to trigger.
> > > 
> > > Ethan and I discussed at LPC and I asked Ethan to come up with a generic way
> > > to trigger the fuzz code that doesn't solely depend on a single users-space
> > > application.
> > > 
> > 
> > FWIW, the included kfuzztest-bridge utility works fine as a separate,
> > in-tree way of triggering the fuzz code. It's definitely not totally
> > standalone, but can be useful with some ad-hoc descriptions and piping
> > through /dev/urandom or similar. (Personally, I think it'd be a really
> > nice way of distributing reproducers.)
> > 
> > The only thing really missing would be having the kfuzztest-bridge
> > interface descriptions available (or, ideally, autogenerated somehow).
> > Maybe a simple wrapper to run it in a loop as a super-basic
> > (non-guided) fuzzer, if you wanted to be fancy.
> > 
> > -- David
> 
> An alternative Ethan and I discussed was implementing only
> FUZZ_TEST_SIMPLE for the initial commit.
> It wouldn't even need the bridge tool, because the inputs are
> unstructured, and triggering them would involve running `head -c N
> /dev/urandom > /sys/kernel/debug/kfuzztest/TEST_NAME/input_simple`
> This won't let us pass complex data structures from the userspace, but
> we can revisit that when there's an actual demand for it.

I feel like we had all this discussion before and I failed to be taken
seriously ;-)

For the record: I'm all for simplifying this. I had [1] looked into
integrating this framework with say afl++ or honggfuzz (the latter is
simpler due to the way coverage feedback is done) *inside* ARCH=um, but
this whole structured approach and lack of discoverability at runtime
(need to parse the debug data out of the kernel binary) basically throws
a wrench into it for (currently) nothing.

[1] other projects have taken precedence for now, unfortunately

And I do think it creates an effective dependency on syzkaller, running
via the bridge tool isn't something you can even do in such a context
since it's "userspace in the kernel" vs. "fuzzer integrated with the
(UML) kernel", you'd have to put the bridge tool into the kernel binary
somehow or so.

So to me, the bridge tool might be great for manual work (initial
development and reproducers) on a test, but I don't really see how it'd
be suitable for fuzzing runs. I expect it'd also be quite a speedbump,
and makes integrating coverage feedback harder too.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9adc2c51cb0b176006c362c26f2b1804a37b48d6.camel%40sipsolutions.net.
