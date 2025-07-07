Return-Path: <kasan-dev+bncBAABBL5YV7BQMGQEPMWCX7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A9A32AFB63E
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 16:39:45 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e0548d7e86sf18417065ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 07:39:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751899184; cv=pass;
        d=google.com; s=arc-20240605;
        b=YR683jEPj6P58S8jn6p7hNngzMS7HXVG7ZaT8QWqiNBhjWJqtXDt3z/CIrz6RQb2p9
         TILClRkM86q50guwU/n00kn6YQWPXfv+NO+nfr1rIK1hu0m5o4vY+aJ9QjWmMvhKMOjg
         NNhYYEgYyI4AGSch3ueMhWxUctw9vLSp9Il0oc9FXi/paebb9YeEiblwfjB0Gn8mHuHH
         bCkobXzHKJhJzSV3Jmtk7KZAXFFfHUOlCwv84gcR3WAw+xHb71iVRzt7/YT0EcZeAK2I
         1BEoQcoJajAEXgyAXrFpOcq+oB1mxdwH00oVQoQSriIk4oHme593EgtYglSeXqHMq1AU
         5paw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xKIkyehGfQCXqQYxRl1kFi3KScowyiu5Mh4Ub7Yusbs=;
        fh=mfbrnVMWe3Pa1oe0gVCNrqR6A9X3UrkHLJgaCb+T1sU=;
        b=UMUJsILr5NFvwlkTaczAoI4lF2geg7za5FTOsBmnYs9fk1qTRhnIFhk7UIoSZVm797
         5wDzQBKdEUVsrrIq5ySsxAkKRFA8pjsKiGrUthegU3Lu7xaCcjaWQcAuMPNmeaJtk0ma
         R4aKDxxzZwskATrGY0HZXcSWkBXwiL21vQCrozZresZ7vr0N/2RAzkLtUpNOrXJ/Bw7t
         QQ489WR+skrPVoTLGZ7ko7l1YNXoBf2jYHSFN6HdATfkJ/vAxmM90RhOubUBm0v3PzQx
         7ZJn4bxngUzbzP2pKiNMeJ2ydCHYFA+mvkv9nllUoc89J6nzGb/te9aDQbTqwNOuOE7s
         Fi0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Mu0gY5q/";
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751899184; x=1752503984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xKIkyehGfQCXqQYxRl1kFi3KScowyiu5Mh4Ub7Yusbs=;
        b=wbi5J/DuVK9hDUxkFBoDx5VjXJTF06hswqX8CsMzh/rvXj2+BtKX1GEeTkA/R1jyJA
         jkMmZgngUmcOzd5oobpLmWIuCxvLX8INVP76L+NekB3vB4iOolNtcGyfzGXsIkBeQy4i
         IuXunUJa73wPS/W2pARDZUvLWXIgzCEhkqK8p2KqUKD7KNnhHC72QGdUZdnMI9xkQmQc
         ZkoFN48tjEsBsty5afiJ6RCWvUt1o8gZZkPsFxqRJljfoRgTCxRqcL+ohIz0UrkH0PbK
         rUJ10qrvHRm22+oxQV59qfbXdb+0br9evqHNoTn8WUfIK9vYI8ykV613lNDbtIa6bbo4
         ltyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751899184; x=1752503984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xKIkyehGfQCXqQYxRl1kFi3KScowyiu5Mh4Ub7Yusbs=;
        b=Mscw0sJQ+za9AS+C0DGlgEGeJq16MBn25mUQ3Wt7N6XQar5F2aMuw0FUo8isfEnAJX
         i6xRy9DkTSeojPDJHpH/lxpZt02EkKXyxREk8flqZNpciED4DLUxzYLpzQFJQ4DzqzMZ
         eVhQHc+OZ2m1kZALvIM2mWdzWl9A9fPh0NNzOdslFQVmJGG/f/nBeOJcuQzR3n01rJIM
         oSJEncRmIps4MO9f9pYSCmQqNzeTnJooodhU70Iez5dCedU6APEu1VlXfcH/6cmYCK9C
         at8QyomlpP8Twbc/Z958jNLz1ENS1HbaqlB7+HSNr+0L5reeshsq7PK5dvyBAny0Q9LO
         +llg==
X-Forwarded-Encrypted: i=2; AJvYcCVkQFsxW3k7qsFrqWGKcG6V0WLmWxbQbPRToMfljodLaZFwciIwqzzeoX5ZW5CZepb/F5fFwA==@lfdr.de
X-Gm-Message-State: AOJu0YyQ5Hrpy2BdRgdruZUNi/Yj+9g9IuxpvQwuvaRHjJSD4pEi8M4g
	yaxJLkg7m1coLrbfvN+PkoRgqu9Aamaw9zJLBInPFkaXv22i4VRbprUc
X-Google-Smtp-Source: AGHT+IHMdQok78Jo0x1ck7DlAaHMUJWzo+OhzghQjIaLc9CA6y1D88n5zfmYzna7+7R+r7TfT3q8BQ==
X-Received: by 2002:a05:6e02:1a4c:b0:3dd:bb7e:f1af with SMTP id e9e14a558f8ab-3e1371f6b2emr116864905ab.20.1751899183903;
        Mon, 07 Jul 2025 07:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGju3YUnYlfvPTmQgg03xfO+XuMBhnZB8GI5E5Hwwe5w==
Received: by 2002:a05:6e02:5e86:b0:3dd:bf83:da96 with SMTP id
 e9e14a558f8ab-3e1391d9516ls18640745ab.2.-pod-prod-09-us; Mon, 07 Jul 2025
 07:39:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5EubKYCETla7l1V/fZ2dgV/o0KcUMWrlZuZstvWNdTjhJSDLRpsyRDPG4RUraqqF2IL2WbTos+e4=@googlegroups.com
X-Received: by 2002:a05:6602:6d05:b0:875:bc7e:26ce with SMTP id ca18e2360f4ac-876e4575f8cmr1164767039f.0.1751899182871;
        Mon, 07 Jul 2025 07:39:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751899182; cv=none;
        d=google.com; s=arc-20240605;
        b=GuVNRlI/T8fb0QxgWxBqRCoE+CsTeIkHgtU+YAwhE3VG0f55mygvWqbR+y0UCsvDnS
         CbTrv22j29vox9EdSwOi6DvyJnx+rfm4NvwbaXrXAWZijXlp4S3EW4WjLE0F9itmwrrv
         c0uhRoUZA2nvrDoK5P7fVpPyL7wRjw/MB2wE9q1wkmF71mI/pdDYrNaOFRVr7/JuGUOa
         ktaMrxMPbzhUEE4uPXRIhAPeDND0KgNohKB7X01DhdyWPYqE+IKwFaJu4RLX7A8Xf7tl
         uZCZjSTsacPGGRJ1jMhbXpC6Miy1rMrgKG1t93urlfwy3pm2IZ0ptt2qHoRDq95GFm7g
         CD4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5uQo5Vc97pDWJCEUVhG8HQ2dc7MeOTiQ+bYt9yMxSY0=;
        fh=ZFmqDGIg7cn7OadhPwrJaXrZ3b0GVPkdcyJRWc1zL1w=;
        b=GYToEXmk2KVnPpX5oete5QRtT8a3mEZ353LKzZJZP96f0d4JCAZ7XeWCg6zVdIt7hW
         a1xGTvjUoDgpxo3vobdV98KnNRHU9DHrocZjaG2GpIrQYZhWjFKTYgUrzxkZt2h0Vdwh
         ojTGAUDQI326GaJ0LfXFGSC+P9VZUwjJ6WpEaBcsmMAT4Davmuyeqe//qLMBOrrcajYC
         w+dqJAX5JX5j5UQGvl0DvvWEp7DV9P8nUao6KNvt25K9pW/q1p7tnbLrWGjjXbIQkvxu
         3KYyHb5kjfjxb3/DNA04sUFmWOzxLQtU5A5phqoSBJ8LwWnURfUmz7m/oYxj9GUZ/YAg
         KwfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Mu0gY5q/";
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-503b5989891si197667173.2.2025.07.07.07.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 07:39:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4E8B35C5961;
	Mon,  7 Jul 2025 14:39:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 36BB9C4CEE3;
	Mon,  7 Jul 2025 14:39:40 +0000 (UTC)
Date: Mon, 7 Jul 2025 16:39:37 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="pzndlq26xqhms7za"
Content-Disposition: inline
In-Reply-To: <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Mu0gY5q/";       spf=pass
 (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--pzndlq26xqhms7za
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>

Hi Marco,

On Mon, Jul 07, 2025 at 09:44:09AM +0200, Marco Elver wrote:
> On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > While doing this, I detected some anomalies in the existing code:
> >
> > mm/kfence/kfence_test.c:
> >
> >         -  The last call to scnprintf() did increment 'cur', but it's
> >            unused after that, so it was dead code.  I've removed the dead
> >            code in this patch.
> 
> That was done to be consistent with the other code for readability,
> and to be clear where the next bytes should be appended (if someone
> decides to append more). There is no runtime dead code, the compiler
> optimizes away the assignment. But I'm indifferent, so removing the
> assignment is fine if you prefer that.

Yeah, I guessed that might be the reason.  I'm fine restoring it if you
prefer it.  I tend to use -Wunused-but-set-variable, but if it is not
used here and doesn't trigger, I guess it's fine to keep it.

> Did you run the tests? Do they pass?

I don't know how to run them.  I've only built the kernel.  If you point
me to instructions on how to run them, I'll do so.  Thanks!

> >         -  'end' is calculated as
> >
> >                 end = &expect[0][sizeof(expect[0] - 1)];
> >
> >            However, the '-1' doesn't seem to be necessary.  When passing
> >            $2 to scnprintf(), the size was specified as 'end - cur'.
> >            And scnprintf() --just like snprintf(3)--, won't write more
> >            than $2 bytes (including the null byte).  That means that
> >            scnprintf() wouldn't write more than
> >
> >                 &expect[0][sizeof(expect[0]) - 1] - expect[0]
> >
> >            which simplifies to
> >
> >                 sizeof(expect[0]) - 1
> >
> >            bytes.  But we have sizeof(expect[0]) bytes available, so
> >            we're wasting one byte entirely.  This is a benign off-by-one
> >            bug.  The two occurrences of this bug will be fixed in a
> >            following patch in this series.
> >
> > mm/kmsan/kmsan_test.c:
> >
> >         The same benign off-by-one bug calculating the remaining size.
> 
> 
> Same - does the test pass?

Same; built the kernel, but didn't know how to run tests.


Have a lovely day!
Alex

> > mm/mempolicy.c:
> >
> >         This file uses the 'p += snprintf()' anti-pattern.  That will
> >         overflow the pointer on truncation, which has undefined
> >         behavior.  Using seprintf(), this bug is fixed.
> >
> >         As in the previous file, here there was also dead code in the
> >         last scnprintf() call, by incrementing a pointer that is not
> >         used after the call.  I've removed the dead code.
> >
> > mm/page_owner.c:
> >
> >         Within print_page_owner(), there are some calls to scnprintf(),
> >         which do report truncation.  And then there are other calls to
> >         snprintf(), where we handle errors (there are two 'goto err').
> >
> >         I've kept the existing error handling, as I trust it's there for
> >         a good reason (i.e., we may want to avoid calling
> >         print_page_owner_memcg() if we truncated before).  Please review
> >         if this amount of error handling is the right one, or if we want
> >         to add or remove some.  For seprintf(), a single test for null
> >         after the last call is enough to detect truncation.
> >
> > mm/slub.c:
> >
> >         Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
> >         using seprintf() we've fixed the bug.
> >
> > Fixes: f99e12b21b84 (2021-07-30; "kfence: add function to mask address bits")
> > [alx: that commit introduced dead code]
> > Fixes: af649773fb25 (2024-07-17; "mm/numa_balancing: teach mpol_to_str about the balancing mode")
> > [alx: that commit added p+=snprintf() calls, which are UB]
> > Fixes: 2291990ab36b (2008-04-28; "mempolicy: clean-up mpol-to-str() mempolicy formatting")
> > [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
> > Fixes: 948927ee9e4f (2013-11-13; "mm, mempolicy: make mpol_to_str robust and always succeed")
> > [alx: that commit changes old code into p+=snprintf(), which is still UB]
> > [alx: that commit also produced dead code by leaving the last 'p+=...']
> > Fixes: d65360f22406 (2022-09-26; "mm/slub: clean up create_unique_id()")
> > [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
> > Cc: Kees Cook <kees@kernel.org>
> > Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
> > Cc: Sven Schnelle <svens@linux.ibm.com>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Heiko Carstens <hca@linux.ibm.com>
> > Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
> > Cc: "Huang, Ying" <ying.huang@intel.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Lee Schermerhorn <lee.schermerhorn@hp.com>
> > Cc: Linus Torvalds <torvalds@linux-foundation.org>
> > Cc: David Rientjes <rientjes@google.com>
> > Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
> > Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > Cc: Chao Yu <chao.yu@oppo.com>
> > Cc: Vlastimil Babka <vbabka@suse.cz>
> > Signed-off-by: Alejandro Colomar <alx@kernel.org>
> > ---
> >  mm/kfence/kfence_test.c | 24 ++++++++++++------------
> >  mm/kmsan/kmsan_test.c   |  4 ++--
> >  mm/mempolicy.c          | 18 +++++++++---------
> >  mm/page_owner.c         | 32 +++++++++++++++++---------------
> >  mm/slub.c               |  5 +++--
> >  5 files changed, 43 insertions(+), 40 deletions(-)
> >
> > diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> > index 00034e37bc9f..ff734c514c03 100644
> > --- a/mm/kfence/kfence_test.c
> > +++ b/mm/kfence/kfence_test.c
> > @@ -113,26 +113,26 @@ static bool report_matches(const struct expect_report *r)
> >         end = &expect[0][sizeof(expect[0]) - 1];
> >         switch (r->type) {
> >         case KFENCE_ERROR_OOB:
> > -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
> > +               cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
> >                                  get_access_type(r));
> >                 break;
> >         case KFENCE_ERROR_UAF:
> > -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
> > +               cur = seprintf(cur, end, "BUG: KFENCE: use-after-free %s",
> >                                  get_access_type(r));
> >                 break;
> >         case KFENCE_ERROR_CORRUPTION:
> > -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
> > +               cur = seprintf(cur, end, "BUG: KFENCE: memory corruption");
> >                 break;
> >         case KFENCE_ERROR_INVALID:
> > -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
> > +               cur = seprintf(cur, end, "BUG: KFENCE: invalid %s",
> >                                  get_access_type(r));
> >                 break;
> >         case KFENCE_ERROR_INVALID_FREE:
> > -               cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
> > +               cur = seprintf(cur, end, "BUG: KFENCE: invalid free");
> >                 break;
> >         }
> >
> > -       scnprintf(cur, end - cur, " in %pS", r->fn);
> > +       seprintf(cur, end, " in %pS", r->fn);
> >         /* The exact offset won't match, remove it; also strip module name. */
> >         cur = strchr(expect[0], '+');
> >         if (cur)
> > @@ -144,26 +144,26 @@ static bool report_matches(const struct expect_report *r)
> >
> >         switch (r->type) {
> >         case KFENCE_ERROR_OOB:
> > -               cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> > +               cur = seprintf(cur, end, "Out-of-bounds %s at", get_access_type(r));
> >                 addr = arch_kfence_test_address(addr);
> >                 break;
> >         case KFENCE_ERROR_UAF:
> > -               cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
> > +               cur = seprintf(cur, end, "Use-after-free %s at", get_access_type(r));
> >                 addr = arch_kfence_test_address(addr);
> >                 break;
> >         case KFENCE_ERROR_CORRUPTION:
> > -               cur += scnprintf(cur, end - cur, "Corrupted memory at");
> > +               cur = seprintf(cur, end, "Corrupted memory at");
> >                 break;
> >         case KFENCE_ERROR_INVALID:
> > -               cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
> > +               cur = seprintf(cur, end, "Invalid %s at", get_access_type(r));
> >                 addr = arch_kfence_test_address(addr);
> >                 break;
> >         case KFENCE_ERROR_INVALID_FREE:
> > -               cur += scnprintf(cur, end - cur, "Invalid free of");
> > +               cur = seprintf(cur, end, "Invalid free of");
> >                 break;
> >         }
> >
> > -       cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
> > +       seprintf(cur, end, " 0x%p", (void *)addr);
> >
> >         spin_lock_irqsave(&observed.lock, flags);
> >         if (!report_available())
> > diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> > index 9733a22c46c1..a062a46b2d24 100644
> > --- a/mm/kmsan/kmsan_test.c
> > +++ b/mm/kmsan/kmsan_test.c
> > @@ -107,9 +107,9 @@ static bool report_matches(const struct expect_report *r)
> >         cur = expected_header;
> >         end = &expected_header[sizeof(expected_header) - 1];
> >
> > -       cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
> > +       cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
> >
> > -       scnprintf(cur, end - cur, " in %s", r->symbol);
> > +       seprintf(cur, end, " in %s", r->symbol);
> >         /* The exact offset won't match, remove it; also strip module name. */
> >         cur = strchr(expected_header, '+');
> >         if (cur)
> > diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> > index b28a1e6ae096..c696e4a6f4c2 100644
> > --- a/mm/mempolicy.c
> > +++ b/mm/mempolicy.c
> > @@ -3359,6 +3359,7 @@ int mpol_parse_str(char *str, struct mempolicy **mpol)
> >  void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
> >  {
> >         char *p = buffer;
> > +       char *e = buffer + maxlen;
> >         nodemask_t nodes = NODE_MASK_NONE;
> >         unsigned short mode = MPOL_DEFAULT;
> >         unsigned short flags = 0;
> > @@ -3384,33 +3385,32 @@ void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
> >                 break;
> >         default:
> >                 WARN_ON_ONCE(1);
> > -               snprintf(p, maxlen, "unknown");
> > +               seprintf(p, e, "unknown");
> >                 return;
> >         }
> >
> > -       p += snprintf(p, maxlen, "%s", policy_modes[mode]);
> > +       p = seprintf(p, e, "%s", policy_modes[mode]);
> >
> >         if (flags & MPOL_MODE_FLAGS) {
> > -               p += snprintf(p, buffer + maxlen - p, "=");
> > +               p = seprintf(p, e, "=");
> >
> >                 /*
> >                  * Static and relative are mutually exclusive.
> >                  */
> >                 if (flags & MPOL_F_STATIC_NODES)
> > -                       p += snprintf(p, buffer + maxlen - p, "static");
> > +                       p = seprintf(p, e, "static");
> >                 else if (flags & MPOL_F_RELATIVE_NODES)
> > -                       p += snprintf(p, buffer + maxlen - p, "relative");
> > +                       p = seprintf(p, e, "relative");
> >
> >                 if (flags & MPOL_F_NUMA_BALANCING) {
> >                         if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
> > -                               p += snprintf(p, buffer + maxlen - p, "|");
> > -                       p += snprintf(p, buffer + maxlen - p, "balancing");
> > +                               p = seprintf(p, e, "|");
> > +                       p = seprintf(p, e, "balancing");
> >                 }
> >         }
> >
> >         if (!nodes_empty(nodes))
> > -               p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
> > -                              nodemask_pr_args(&nodes));
> > +               seprintf(p, e, ":%*pbl", nodemask_pr_args(&nodes));
> >  }
> >
> >  #ifdef CONFIG_SYSFS
> > diff --git a/mm/page_owner.c b/mm/page_owner.c
> > index cc4a6916eec6..5811738e3320 100644
> > --- a/mm/page_owner.c
> > +++ b/mm/page_owner.c
> > @@ -496,7 +496,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
> >  /*
> >   * Looking for memcg information and print it out
> >   */
> > -static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> > +static inline char *print_page_owner_memcg(char *p, const char end[0],
> >                                          struct page *page)
> >  {
> >  #ifdef CONFIG_MEMCG
> > @@ -511,8 +511,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> >                 goto out_unlock;
> >
> >         if (memcg_data & MEMCG_DATA_OBJEXTS)
> > -               ret += scnprintf(kbuf + ret, count - ret,
> > -                               "Slab cache page\n");
> > +               p = seprintf(p, end, "Slab cache page\n");
> >
> >         memcg = page_memcg_check(page);
> >         if (!memcg)
> > @@ -520,7 +519,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> >
> >         online = (memcg->css.flags & CSS_ONLINE);
> >         cgroup_name(memcg->css.cgroup, name, sizeof(name));
> > -       ret += scnprintf(kbuf + ret, count - ret,
> > +       p = seprintf(p, end,
> >                         "Charged %sto %smemcg %s\n",
> >                         PageMemcgKmem(page) ? "(via objcg) " : "",
> >                         online ? "" : "offline ",
> > @@ -529,7 +528,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
> >         rcu_read_unlock();
> >  #endif /* CONFIG_MEMCG */
> >
> > -       return ret;
> > +       return p;
> >  }
> >
> >  static ssize_t
> > @@ -538,14 +537,16 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
> >                 depot_stack_handle_t handle)
> >  {
> >         int ret, pageblock_mt, page_mt;
> > -       char *kbuf;
> > +       char *kbuf, *p, *e;
> >
> >         count = min_t(size_t, count, PAGE_SIZE);
> >         kbuf = kmalloc(count, GFP_KERNEL);
> >         if (!kbuf)
> >                 return -ENOMEM;
> >
> > -       ret = scnprintf(kbuf, count,
> > +       p = kbuf;
> > +       e = kbuf + count;
> > +       p = seprintf(p, e,
> >                         "Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
> >                         page_owner->order, page_owner->gfp_mask,
> >                         &page_owner->gfp_mask, page_owner->pid,
> > @@ -555,7 +556,7 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
> >         /* Print information relevant to grouping pages by mobility */
> >         pageblock_mt = get_pageblock_migratetype(page);
> >         page_mt  = gfp_migratetype(page_owner->gfp_mask);
> > -       ret += scnprintf(kbuf + ret, count - ret,
> > +       p = seprintf(p, e,
> >                         "PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
> >                         pfn,
> >                         migratetype_names[page_mt],
> > @@ -563,22 +564,23 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
> >                         migratetype_names[pageblock_mt],
> >                         &page->flags);
> >
> > -       ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
> > -       if (ret >= count)
> > -               goto err;
> > +       p = stack_depot_seprint(handle, p, e, 0);
> > +       if (p == NULL)
> > +               goto err;  // XXX: Should we remove this error handling?
> >
> >         if (page_owner->last_migrate_reason != -1) {
> > -               ret += scnprintf(kbuf + ret, count - ret,
> > +               p = seprintf(p, e,
> >                         "Page has been migrated, last migrate reason: %s\n",
> >                         migrate_reason_names[page_owner->last_migrate_reason]);
> >         }
> >
> > -       ret = print_page_owner_memcg(kbuf, count, ret, page);
> > +       p = print_page_owner_memcg(p, e, page);
> >
> > -       ret += snprintf(kbuf + ret, count - ret, "\n");
> > -       if (ret >= count)
> > +       p = seprintf(p, e, "\n");
> > +       if (p == NULL)
> >                 goto err;
> >
> > +       ret = p - kbuf;
> >         if (copy_to_user(buf, kbuf, ret))
> >                 ret = -EFAULT;
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index be8b09e09d30..b67c6ca0d0f7 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -7451,6 +7451,7 @@ static char *create_unique_id(struct kmem_cache *s)
> >  {
> >         char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
> >         char *p = name;
> > +       char *e = name + ID_STR_LENGTH;
> >
> >         if (!name)
> >                 return ERR_PTR(-ENOMEM);
> > @@ -7475,9 +7476,9 @@ static char *create_unique_id(struct kmem_cache *s)
> >                 *p++ = 'A';
> >         if (p != name + 1)
> >                 *p++ = '-';
> > -       p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
> > +       p = seprintf(p, e, "%07u", s->size);
> >
> > -       if (WARN_ON(p > name + ID_STR_LENGTH - 1)) {
> > +       if (WARN_ON(p == NULL)) {
> >                 kfree(name);
> >                 return ERR_PTR(-EINVAL);
> >         }
> > --
> > 2.50.0
> >

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6%40jbt6dwnzs67r.

--pzndlq26xqhms7za
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhr3CEACgkQ64mZXMKQ
wqk4aA/+Mvv63Bmz7LwbWP8jHRGdodX7lT887AsPc0MIl1gzOpJQDO5mawJIKZ2O
Ezz2CFlK0W3da0JvdHK8QoIoyR/NV0+KxOfyliTUDn21rOMmDqH0Y7qE0i9gCLA3
GIIAD3K2WgQf6HMHpbZsGYQTYsOz8lr1mHmE6QHeaaLvlaux4Sa6DeZPAGG3rU7/
NOZvqadKOlS+oNWkgeENZeINRGNsxbldMLuKd3XfR/WTJg1oLzJiiQgTIO1o/X1F
FjwdbCAQMDOcgp9yBPqfm3XfQgiAUtVBt6sOQks7r9+mTHIE7D6eBaXnDSZf+cry
BzQ85B/ABW5MFYG7f7zp21FS7DLivXyRHI60ZFCT/i+fPOxA+mRUbRgv2A0WlMLY
7dL0+7y6RvV+Q53r7ecH8VaBgxoFUN37KJE6fSR1TRI+H0tizGS5w//HRU+Ahods
cFN+w7/TJb7c+1hOTE86MXp28dXEZ7qsHIwlh67aL4F4LaVtzstmp8RgdKRXwYcO
M5PzWaLgRBsvSK0TavaypccT4+mWlsGEiy5K0CV4hu2bXultKXnbxbFmV3XQ77Dx
sc1FRzM0HVT/FJ95KiqREeqRIVK4+MogvZEadOqidPvio7pob6CLXrKAHJg3valr
WSf7uk/yJC61MlWf7gKEbFzQD4/Nnkgum229f2FHj6es6MtYDzs=
=TrTS
-----END PGP SIGNATURE-----

--pzndlq26xqhms7za--
