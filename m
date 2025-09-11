Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBYNLRPDAMGQEB5IRMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 97060B534B9
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 16:00:06 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-625b1922a37sf884008a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 07:00:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757599203; cv=pass;
        d=google.com; s=arc-20240605;
        b=aXnVENxMkfx61iQz0jQWRgoj1gp8p6n4bN9k4sazEFDokd+8xcAq+iaSkNXfH1Wo3j
         4cJddwNmIlNdSfE22PjUF/fuveiwU3JzoG9qxnojkKgpRnbkVSUTvgQCSKY7Ht+R00KV
         UG0ZKTNFnFC0KeergvBPh4c6kXybA1dPsn7BURnvUncJfOgPN6Xd6pvAyy2WkxrYH8OB
         /edb4IvXPvphIuWtSemEpxkMODr+gkcu8gLe6OzP1q4rcQ3B8n3dc9FeXE1KkuClurXG
         yHktvS1lRd+vpoB2WRju2p+rU/FcxXm2wc1gaweNrXkeyiYDTFjdN3xRGYp8s4raUggQ
         OE6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=bqbypKwnlILV6fk7RYA4mgTP/TMutWN5SlblpUUjQTg=;
        fh=fYY4UYSBJoCDoUpk23ta6hip467ekY96ZSnAVA5PVOY=;
        b=B5oeQinyiEBGzMUH0nHrvhyaoq88gatjsaqpCo5GmDI5vxR49OxspupJ7MsqOBlTpS
         sdDxWf77bKUue7s/vGmsFVK1NW01KLW+nqsq9YtOpLel5Q1AbopT0QeAQ62DlDk/0wie
         WTZuhOmgQFXxWWOQK1Bpg3wREcx8Y+LfZu9XL0Rdim7Rl4DWHzOzpUM5dHG4ikkQ35sW
         HxP4u3awqq3LAXiPphmJuZ0BYHh16cl9ZmwUYz4GfYs5h8JShWW4GJOJcHSK6Kvw5H6n
         SVi3osStSIHIGfn4t5J4Pno4HW3d3o9BraeyxO/VwRa6lCQ6GNWuG7Z1Udgw/k6GdOfy
         W82Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=dNYYH4AG;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757599203; x=1758204003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bqbypKwnlILV6fk7RYA4mgTP/TMutWN5SlblpUUjQTg=;
        b=EadrdXNxr0furuCa0GOK3tkKI03ifyO878Egzy2oBUUpfqdH/yg6ZJH188YjyVgnua
         scaqXIDB/ThorHn9qe9hvs3Bdl8GquJMmGiDWgAu3VP/8pe1BplAYO9iQhDOFApsUKWB
         AhEyA4bxwn48uFh+sXnpwcjQO2CmzhJB+nCPy1jp5qSn3tXellyK4n0TNR+GEbdwzfKF
         k5IV4ykRtNl3H1O/eL8UJeUkhd785Z4VT8F2LzG4heOsOr2MMHioVnEO69JdJ3ePyvRg
         9sIsAj8AEzy++dOc8ouBkFQwi0YJeVhBTT7vgsBQeAOC+trpXD/loNMwFS6Qu+uiD4xW
         yJ6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757599203; x=1758204003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bqbypKwnlILV6fk7RYA4mgTP/TMutWN5SlblpUUjQTg=;
        b=A9rLtIV1YX5faI5lYMLvkH1/jydGWIBw3FVHUB9pvXBR0okjZ3JgFuFqetHbmbDiiK
         wCIlubL8nwqddB/5pCC+mUqAkIHVvj7S788z6gSb3tLimLpmWl0bGPoMTwZ1IT784hTu
         tyO3+kniYCfvVms6odXwx8CRYisA40Qb9uLbGgwTZAaNuwmpEWGlUBlnfeeUakE4Eisk
         u0WLe7oerEUwJQZx2zdKG/4bvt+5At1Me5BvtQ50mWoPfdPCDjqmKLdXY/6Ih2J2E37Y
         kXavC212BQxIX2rH2sZP+z2/z5659jOqq6pWxapNrNPc41pS0Vq5e9tE9Wi2wHTKoOWi
         xI6Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWztQVYcy8Rdv6dPHEYgAUKKk3t0a1h2YSSAuTkdpKJdEAEDpTocz/k5LaJRnK5w8oeLwCEag==@lfdr.de
X-Gm-Message-State: AOJu0YxY8MsWdJ/BR9mfpaBNAVnAevoTmxlKKzvO/IYnmg6iVjkU3UFS
	f1LMuNFouU4VTLd05Fo+fx4OvGwd9xVCP0vNs+8jhEpBrBcTCdJS2DwD
X-Google-Smtp-Source: AGHT+IEAIqXVz/vFs/35aBiW8AP9K2iE0Yi0SwVYc5WrpuPIpwr98mDDZBqa5/9Nx/ZfUnO5MfYtnA==
X-Received: by 2002:a05:6402:1d52:b0:626:6ce5:4b8 with SMTP id 4fb4d7f45d1cf-6266ce50670mr17161233a12.32.1757599202178;
        Thu, 11 Sep 2025 07:00:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6B9vyJjhbqyFa4KrS5IByrfAgK/m6P8eAniots+Sp/Tw==
Received: by 2002:a05:6402:439b:b0:61c:8922:33b1 with SMTP id
 4fb4d7f45d1cf-62ebe040981ls767240a12.2.-pod-prod-03-eu; Thu, 11 Sep 2025
 06:59:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIhXYiZqtOQhvkfn/XHocjBpYgDGSYhBor/utzMdvSu+pyV84Lfekk/8bA89lhF7NUZa9VH+pI7y4=@googlegroups.com
X-Received: by 2002:a17:907:96a0:b0:b04:7b7f:33cc with SMTP id a640c23a62f3a-b04b173895dmr1869118966b.62.1757599199307;
        Thu, 11 Sep 2025 06:59:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757599199; cv=none;
        d=google.com; s=arc-20240605;
        b=fAcqSKFxTG/hmXh89OqtDO5OzI08pN57v0YDlUWgkHKnP4zZGtp0SQ0yt7/HyKHF9H
         F3JaQpTqsRhn5DF/+aL7uk0aSMQyhFbjum3anxkUR3OhUM9rVfSujx4z4IPHmcL2bsjB
         aB5GuiOf29dkSTD+Dbg00jPlql+OzSmdwp5kBNTBdYetbYnGTbvua7tbNMxEkyOadx6m
         TVFAqyRuen6m2sC1OuCZRNjFUaKINMqN5MZm5sFgdqugIL9+zLN6kfZbLhCxPO+wu0b5
         mOzjvc0MuqbcbKgtymDuNZpOh8Bu8BrDq31tNDJyurA3yiYTcpZI8XNxzjri24yaNYEU
         NP6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=1ZpIIGiAzp9dlmnlhXDwO9rr0Iyle3/GOpYyQPgYY/c=;
        fh=YP+DEuyyQJUxw35gMltrpE/KiLFZ4UavdZBWehXpHn0=;
        b=B14PFnATAPcI+1uELPdPg1ncp31NnGKUgD6Wc9j7d1lnFq0JQcApMz0GoCcCAPlalW
         jsRi7xSYL6XS9yZBY4z6MfepijrzeHmwUtuHUqHH8JozKkUgB36d5BOtxrJIw1Uc7hFe
         C83KX01Pc79FrZw87YnGKdwaWOfEuHTxbPZ7c30He4WA9lfZMOTSOTuxcMc+dgXTqM4o
         8/x2hVxToXvMGp976quH0bMSSSEDbYHiccw73Ls75alpK+YkDWGj6gHdUvcCRVxJ0eF0
         Z5v1ZKAJUjo3eEkZYN8LX6JZJtH2qfbwozsLfi3xmMuE9tJv/QjhYT8UNVqHIsdtwy6H
         7lJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=dNYYH4AG;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b07b316e1ffsi3463466b.2.2025.09.11.06.59.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 06:59:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1uwhq3-0000000FP2l-2ojG;
	Thu, 11 Sep 2025 15:59:51 +0200
Message-ID: <cf3eef898266e5a8064c6cc5d2c12a9b0971f75c.camel@sipsolutions.net>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Alexander Potapenko <glider@google.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	andreyknvl@gmail.com, brendan.higgins@linux.dev, davidgow@google.com, 
	dvyukov@google.com, jannh@google.com, elver@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, 	dhowells@redhat.com, lukas@wunner.de,
 ignat@cloudflare.com, 	herbert@gondor.apana.org.au, davem@davemloft.net,
 linux-crypto@vger.kernel.org
Date: Thu, 11 Sep 2025 15:59:50 +0200
In-Reply-To: <6eda1208c08130e00cb54e557bc4858ce10a4a94.camel@sipsolutions.net>
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
		 <513c854db04a727a20ad1fb01423497b3428eea6.camel@sipsolutions.net>
		 <CAG_fn=Vco04b9mUPgA1Du28+P4q4wgKNk6huCzU34XWitCL8iQ@mail.gmail.com>
		 (sfid-20250910_124126_320471_24812999) <6eda1208c08130e00cb54e557bc4858ce10a4a94.camel@sipsolutions.net>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=dNYYH4AG;       spf=pass
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

Hi again :-)

So I've been spending another day on this, looking at kafl/nyx as
promised, and thinking about afl++ integration.

> I've been looking also at broader fuzzing tools such as nyx-fuzz and
> related kafl [1] which are cool in theory (and are intended to address
> your "cannot fork VMs quickly enough" issue), but ... while running a
> modified host kernel etc. is sufficient for research, it's practically
> impossible for deploying things since you have to stay on top of
> security etc.
> 
> [1] https://intellabs.github.io/kAFL/tutorials/linux/fuzzing_linux_kernel.html
> 
> That said, it seems to me that upstream kvm code actually has Intel-PT
> support and also dirty page logging (presumably for VM migration), so
> I'm not entirely sure what the nyx/kafl host kernel actually really
> adds. But I have yet to research this in detail, I've now asked some
> folks at Intel who work(ed) on it.

It's actually a bit more nuanced - it can work without Intel-PT using
instrumentation for feedback and using the upstream kvm PML APIs, but
then it requires the "vmware backdoor" enabled.

Also, the qemu they have is based on version 4.2, according to the bug
tracker there were two failed attempts at forward-porting it.


> Which I'm not arguing is bad, quite the opposite, but I'm also close to
> just giving up on the whole UML thing precisely _because_ of it, since
> there's no way anyone can compete with Google's deployment, and adding
> somewhat competing infrastructure to the kernel will just complicate
> matters. Which is maybe unfortunate, because a fork/fuzz model often
> seems more usable in practice, and in particular can also be used more
> easily for regression tests.

Or maybe not given the state of the kafl/nyx world... :)

I also just spent a bunch of time looking at integrating afl++ with kcov
and it seems ... tricky? There seem to be assumptions on the data format
in afl++, but the kcov data format is entirely different, both for block
and compare tracking. I think it could be made to work most easily by
first supporting -fsanitize-coverage=trace-pc-guard in kcov (which is
clang only at this point), and adding a new KCOV_TRACE_ mode for it, one
that indexes by guard pointer and assigns incrementing numbers to those
like afl does, or so?

I'd think it'd be useful to also be able to run afl++ on the kfuzztests
proposed here by forwarding the kcov data. For this though, it seems it
might also be useful to actually wait for remote kcov to finish? Yeah
there's still the whole state issue, but at least (remote) kcov will
only trace code that's actually relevant to the injected data. This
would be with afl running as a normal userspace process against the
kfuzztest of the kernel it's running in, but with some additional setup
it'd also be possible to apply it to UML with forking to avoid state
issues.

(And yes, kcov seems to work fine on UML.)

I guess I'll go play with this some unless someone sees total show-
stoppers.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cf3eef898266e5a8064c6cc5d2c12a9b0971f75c.camel%40sipsolutions.net.
