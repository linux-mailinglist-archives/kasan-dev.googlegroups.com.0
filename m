Return-Path: <kasan-dev+bncBC4LN7MPQ4HRB3HX2X2AKGQEFQMF6UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EE781A76CB
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 11:01:33 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id h184sf353495wmf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 02:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586854892; cv=pass;
        d=google.com; s=arc-20160816;
        b=GgtZ3AipRmPugvMyr85W/dwQaQ4iSEeU3VUR7vti4metA1KXNVWMBrJHVt2lfHHZSN
         f4e8ELLnpHzvnrhkpFLfBpZcrHyiDYhuNW9ik5dc0UInqZPsmqCAYmpRngjCQX6LdaZh
         svttllZgbNp7JGrGZACnPEO9U3NG01RawS4iMdStrgOWRzXyEphRQuBNBlL9Crfz6Ypv
         Qhw3dv/3EO47sprFATE694nuNV/IWS3AGmqQU2k0oUgroPG0Z/GJqaZwTdDA+vyMFAs1
         Oiz6bJ3K7bO/q+AthE+cYO7B0HnRs6RvUsiOGAGwqjFlkbphvNXBANXxuCjyd8g9nb4Y
         s0KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y1Zfu9hhS1qh/i9zrtECs+U9kG2BjJmg/uEEIhDwDRk=;
        b=HwAtDexqVuclJs1cxl+ex/01R42DhZU39wdGJ3cqvGN50EVYK5fnyCwWCbpF45wqL/
         V57redkdVKhpxgS2FIBCXq9vcMzH/9yexSGphdrt+/9gURqzU3oUy18tklw4wL2ImBpz
         GFzpN1zjLWoGkeZRsrWvEXsl+TLbHN1zbN8IPWg2YjATSl91nJFyHvcquUUZ6IinttDt
         a5TL7Qf9PQx1uGrm/IW2zuH4FO3FeKoWXshl6eHN6/9oKT7TC3v/w7/kMxVWSxpuWCxR
         mPe1yWtVr2T+U4hPgSAGJoGYTtRO8InF04lLzT9UbjE4yjN7Mz61dUSx+r00d1h2IfGQ
         k2XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y1Zfu9hhS1qh/i9zrtECs+U9kG2BjJmg/uEEIhDwDRk=;
        b=OffWxi7/OzddjqdXxqH0AJpioawjRZd9QltuyTQn4SpcDLOEdtXeKDudJcqzSEaFir
         3iot3ENqOmNJFfyLB8bQVm8HO5TKkiMLZVHdTxRG35DJUg6+I/RsrOV0EVtywVTBtne5
         0b/o8rZktjHyl8k4wDmuq5RmIF86ju8pixvhCuAKM2pJB+IXKoMDo+D7VZ0rq2f0carH
         tRqBPZXM7B/Vg/VVq/S3wPjcmtuW118W2v9jJrQPtELu8vd1NlPLFoP1VPRAXGmjdpyL
         Z94tt0BIr31mxSUuR5F2kxXzI72GyPc8zBZjXQi9HTk/tDKFwhhhR3yQu8XOJkeHw8ZW
         7/sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y1Zfu9hhS1qh/i9zrtECs+U9kG2BjJmg/uEEIhDwDRk=;
        b=YVMy+GUN14qyMQb8i3v38xSf8lHSJyafxG0QX1uWYt5Dr5vlfDemZHn9zeXDD1XS9r
         yyU1E8kuV0wx4VBMkfdaRt4pDJxLKZbF5ulq2xqvjHzSDC9iuu/qe9sX3TlDtdqOpcGJ
         zcz0yz9GgAiTPM02LU7xmLkG3A8XWPJpwPOc0WajRy7XS0Irm/f3P6gq8UByE3nov5Na
         +oSJCxWxuOuCH3gMjxugYW/GK5BjhoDnynP5G/WtNBk7NwCD4bi6mSPphn9jWGmugJvl
         A4I8SByDXLPkg2LmB4YuurBg3b+NVq9AuKuiTOftig07YEPvJ1sYbLxJzEWWj2WIMmmN
         1OLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZtnzbNQvUWf4XRvRZt5K2zjdWl6XCBvYYLtbRoYrkbIosbjcz0
	Gd1WBQjfYjJoAtmmfdbydoo=
X-Google-Smtp-Source: APiQypJpZmaZagyhlGmNxbC+dQCKMm45UHJWk0Njohdl+SzOolmLXP/oGF7RSAZ4NBOdAOyOnKPK5w==
X-Received: by 2002:adf:e7ca:: with SMTP id e10mr521122wrn.18.1586854892766;
        Tue, 14 Apr 2020 02:01:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5644:: with SMTP id k65ls2809382wmb.1.gmail; Tue, 14 Apr
 2020 02:01:32 -0700 (PDT)
X-Received: by 2002:a1c:6344:: with SMTP id x65mr22967904wmb.56.1586854892152;
        Tue, 14 Apr 2020 02:01:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586854892; cv=none;
        d=google.com; s=arc-20160816;
        b=ziGlWdx7+cQWqMOOURpHGaAoq7NfJWUbmqvGMYexhOmFpnnwgdio5RO5AWmW/2ezgM
         qjL+3QQW7Szi2MMbrDrIOlK0eUUhLfhPz/faJ+prmP9HKeT5ra3pskWw7mM6xO2xTYyc
         ++8NUcM840gqr/zfUX5eDpfu3cQa1tMknU0YhkiZAGzZdJV9GHEN13TphF2bGpkPbhdw
         JgOM7wPg4sSzHcj0ZFH9jhfSuvN8512OXouGFw1vJ+6RYGtg7mN5W/tgQIssPNb17R+r
         +t24ToqPSWzy/4gvKd+Bl1TmL9SdeOKxGrDGPfR2SGKNiDJflpHJWxyN3dDC437P3A2R
         2ltA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ZSEHFc2eh+N6K60wyVHbBWfK0AmjMN90oe2OMNtMMJ0=;
        b=a1Iyy7Vby32BZJLwoDvKCSKWKR55/KYOTXhezjLOBoEkNqJqICkSfZryfVdC9b6cW4
         kVHS/fLhmRoQc+O3l6JPvGg4UDDwk6fiiFBQVta4hGjAZwHTHSuOI1e5ExpmoiMBXdPZ
         ZTxPK4pHqJWsXWsA8krcHXcCvsl/FN/NuzrY7B4wIriM+9bZ0hfV5yKviI3yUbYQgQBo
         BQezR2N2Uv7ku640GagEo5MS6yhj+45GBJxKbuQWBIJJQqhnFHVOzzuqVV01Z3h4d/Dr
         soz3+ozaFd2clHeD0WtIkm5QLccUhDXkzUrLnwCa7EBojUmr30J2NDmKKKtDweCtN98P
         0y5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mstsxfx@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=mstsxfx@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-f68.google.com (mail-wm1-f68.google.com. [209.85.128.68])
        by gmr-mx.google.com with ESMTPS id o125si909930wme.4.2020.04.14.02.01.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 02:01:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mstsxfx@gmail.com designates 209.85.128.68 as permitted sender) client-ip=209.85.128.68;
Received: by mail-wm1-f68.google.com with SMTP id a201so12686554wme.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 02:01:32 -0700 (PDT)
X-Received: by 2002:a1c:a913:: with SMTP id s19mr23660673wme.134.1586854891811;
        Tue, 14 Apr 2020 02:01:31 -0700 (PDT)
Received: from localhost (ip-37-188-180-223.eurotel.cz. [37.188.180.223])
        by smtp.gmail.com with ESMTPSA id n6sm18637096wrs.81.2020.04.14.02.01.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Apr 2020 02:01:30 -0700 (PDT)
Date: Tue, 14 Apr 2020 11:01:29 +0200
From: Michal Hocko <mhocko@kernel.org>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200414090129.GE4629@dhcp22.suse.cz>
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
X-Original-Sender: mhocko@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mstsxfx@gmail.com designates 209.85.128.68 as
 permitted sender) smtp.mailfrom=mstsxfx@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon 13-04-20 17:15:49, Waiman Long wrote:
> As said by Linus:
> 
>   A symmetric naming is only helpful if it implies symmetries in use.
>   Otherwise it's actively misleading.
> 
>   In "kzalloc()", the z is meaningful and an important part of what the
>   caller wants.
> 
>   In "kzfree()", the z is actively detrimental, because maybe in the
>   future we really _might_ want to use that "memfill(0xdeadbeef)" or
>   something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. In addition, memzero_explicit() is used to clear the
> memory to make sure that it won't get optimized away by the compiler.
> 
> The renaming is done by using the command sequence:
> 
>   git grep -w --name-only kzfree |\
>   xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
> 
> followed by some editing of the kfree_sensitive() kerneldoc and the
> use of memzero_explicit() instead of memset().
> 
> Suggested-by: Joe Perches <joe@perches.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Makes sense. I haven't checked all the conversions and will rely on the
script doing the right thing. The core MM part is correct.

Acked-by: Michal Hocko <mhocko@suse.com>
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414090129.GE4629%40dhcp22.suse.cz.
