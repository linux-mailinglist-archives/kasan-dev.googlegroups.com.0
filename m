Return-Path: <kasan-dev+bncBCLI747UVAFRBNODUT3QKGQEMGOBWJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 17B011FBF47
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 21:47:03 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id c22sf17619699qtp.9
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 12:47:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592336822; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDWq2yOqSR2Dmg086dC65cbjedH1drWMPQEKN2P15MplB6xSa2MgoWtwwoWiJQYjZA
         7HoZZIrwMKx6Ikk9iGGWj52i4mVe1/citH/gLGPHIAchCPkU7LTQPeEXUU9NJ+wy+sK4
         f2lZj/qz+HEkAKBaDpfRwh9XX5vfZjCbekMCPiKcob1NI+xUAWvEUplFcW7MLCI320NX
         Dsvo0AQ+3i0zQNYrD4mr+GLT6C02U23rerwO3/zuV6FZ+Ets1ngWUPC2b9fwAzwlOjqZ
         +E1Y+s7rFFfuJKiaLB4n7HAVRDTjWy0Iq5zH9UpWs2m/AfIg48TZgN78t/erzixxOgbh
         cmGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=c/UrMMxdUkdDy4D6cXRRIvTSFR/PuD8HXkBo4yuO6PE=;
        b=w/5WMgIheoOi/+ZCpx1f9vGJAA/lWUVjYBBu/rkT1nmLMT88CP2H7FkELHQ09Lq1zE
         6lS5xMnr2NB6lODcL05FlweEe8glUgB+aiwyX2UPFjRQozG5MYNr/x+teW6WEEyO3VCd
         MPnXs9SjxALVvq6nC6EKpDk59WN/EcseuG5CY7B4KI8md2j+KP7NYl8uXcHfxEB/kbqd
         Ty5Mhdd5ULoizNHjLp+oYet97G8qvjFa6YigxAewonkhTIlv+7dta9+tPXCEW1CsItEe
         qfP14iPVYwGgjp7500KXOFMHKwYmmywy0b+Fk2UiuYROM07K9lOBoxAZ0sGt53/5QsSD
         ugSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=mail header.b=auHBa5AE;
       spf=pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) smtp.mailfrom=Jason@zx2c4.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c/UrMMxdUkdDy4D6cXRRIvTSFR/PuD8HXkBo4yuO6PE=;
        b=c4ZcFJse5nhrtPrtHfaH+85cwETcV36nsoaKOnhk+ikZg1upU080sDP5fQGCzMsiap
         6GAmsRo3jN2mkB1N6yRD9Kjp1p/ARDCY6EJtZpmil5zfRs89+Lo9FQjpx0QBS9Ynd96P
         SZwr9uOGZjxuIFPDKrcyZOqs/qGZ/ARwKjWYrkkA8HB/plaOw/l/zV43ObNdJgnHeQ/2
         zx3/3XiCY9wbVM8PNvC04hMLtrCOQq/Y4iE4MnuT3OS9k+LgtZipbjt7l/sZbojVO1sV
         Ea3FOO0fBDkFFxbXiLIZFkh/DOcSY8nerWNvqAmfsDQV5/ORkGurY5bqo+2sbWoh7XKg
         TZiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c/UrMMxdUkdDy4D6cXRRIvTSFR/PuD8HXkBo4yuO6PE=;
        b=q7MhY70gpE67sqM/UmNAPrvyrQ1W7WqRGzZ6+LE6BJ4SinGXjRwpQAc45XaWAAm/x/
         qi70UADCa5xjFlnfejjYN0dJtXZnAEz7r3Es+aoj2gj8FY/M7+5gXa36B83u1c+aDz0J
         28CLaf2tpa26Il0+eoCZCCQOnyHYxpYbGhPJy7QJ/IFzH7rR4HDmiI/f5xO2haXo03Vj
         fva+M3ijiJgWCtnFV9WGH6EoxxhIFf0yYdxr7ipenuWKdSk0gIttWshQrzlYH7lzNVHu
         3bwroYQjpyX1qQfB4Rq8G/gINjxsasscpSHV5RkR0a6bEr9OG9KSwwVovQ7jBi8K0kxY
         5n/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53214PIZdjZLvQtqRrUyeBwnMi/Rnse+lSFlMM1chGxq+3yFKv32
	3kwnk/HO2hQgsmSwEiQXJtY=
X-Google-Smtp-Source: ABdhPJzW8Q1cGZ0AxEZ9vNJSnaFm7KRemCa63hYRplyo1jaM8l73r0mc/fQzFSyZrukVpU65561DNQ==
X-Received: by 2002:ae9:e70e:: with SMTP id m14mr3187107qka.144.1592336822040;
        Tue, 16 Jun 2020 12:47:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:2756:: with SMTP id n83ls8813874qkn.1.gmail; Tue, 16 Jun
 2020 12:47:01 -0700 (PDT)
X-Received: by 2002:a37:a14b:: with SMTP id k72mr3674895qke.296.1592336821562;
        Tue, 16 Jun 2020 12:47:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592336821; cv=none;
        d=google.com; s=arc-20160816;
        b=RMx1ExDqm1kHnCq4c+rjypl32IRPns/8DjxAcZSw78pl1m3PdDfeIKMktju44vGI7v
         x+XQMTTRyl7Ny0z1EZVjrOsJR39AoofawRjbWA6noXVSS1eEFd2xxybae9Ab/VONLlFm
         BUXtTGy7akAh2wQ335EpdpIzwVpXNhEQgFZz+K6XV12ELJ2DPuudkbf28ql3MetkAP86
         UDTJfRAZ0o0P8VR4n2sghyrF0WSuOe+4n66hHo77PT8n6ZSiuGxU8k+NbuD1l26LnIVL
         kujWfC5UiKYn+E/42r8oXtal7JpDqCINoIUyGUdP0erBgttHZYVqmyISSbMrGCZBQx3E
         WR4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0cvVzHmXp02J7DUDVHnlOUzlhMCv1327YXVamlnn2Yk=;
        b=hG8gh9SK8DFnY5dS2rTvpBK+AjTqQ/T/uvvqswz8CZjD3HSitf34jFXiZp1l0rNPev
         WW+q2xn7uLUMbqnJl6U3O4fvYnhzCQOYjovDx07BQPBAl2FiUC/TnnGqFhTb5AcMGeq8
         k824T4jFmhmIRx2IVZjRTAfNjmpv0LtBwOHh4KFigTYCe2lB2cB4iLdjkP7Qt9LqyCx9
         TG+AyToNJ0tc7J+AcSFN2C5USG/AcJxal3gCRciy3Wj7taYBEW1LCCukP9Xm3e7GnSoB
         W27FmhlwRGB5Aq6SkoDKjAhjdojxNqM+h/LCqRR5TxlhLdb0BqLlMUXXARS2jZa9nbH5
         Fmxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=mail header.b=auHBa5AE;
       spf=pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) smtp.mailfrom=Jason@zx2c4.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from mail.zx2c4.com (mail.zx2c4.com. [192.95.5.64])
        by gmr-mx.google.com with ESMTPS id y21si1385919qka.2.2020.06.16.12.47.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Jun 2020 12:47:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted sender) client-ip=192.95.5.64;
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTP id 4e534aaf
	for <kasan-dev@googlegroups.com>;
	Tue, 16 Jun 2020 19:29:01 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5b1abff7 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Tue, 16 Jun 2020 19:28:59 +0000 (UTC)
Received: by mail-pg1-f182.google.com with SMTP id l63so14447pge.12
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 12:46:59 -0700 (PDT)
X-Received: by 2002:a6b:6705:: with SMTP id b5mr4346341ioc.29.1592336817452;
 Tue, 16 Jun 2020 12:46:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200616015718.7812-1-longman@redhat.com> <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
In-Reply-To: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Date: Tue, 16 Jun 2020 13:46:46 -0600
X-Gmail-Original-Message-ID: <CAHmME9rCD1KJNguthAhZ+OAVZTpBwEvGRLRV0tvQjBaEYG1bHQ@mail.gmail.com>
Message-ID: <CAHmME9rCD1KJNguthAhZ+OAVZTpBwEvGRLRV0tvQjBaEYG1bHQ@mail.gmail.com>
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Joe Perches <joe@perches.com>
Cc: Waiman Long <longman@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Howells <dhowells@redhat.com>, Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Matthew Wilcox <willy@infradead.org>, 
	David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	David Sterba <dsterba@suse.cz>, Linux-MM <linux-mm@kvack.org>, keyrings@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-pm@vger.kernel.org, 
	linux-stm32@st-md-mailman.stormreply.com, linux-amlogic@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org, 
	virtualization@lists.linux-foundation.org, Netdev <netdev@vger.kernel.org>, 
	linux-ppp@vger.kernel.org, WireGuard mailing list <wireguard@lists.zx2c4.com>, 
	linux-wireless <linux-wireless@vger.kernel.org>, devel@driverdev.osuosl.org, 
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org, 
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org, 
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org, 
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org, 
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net, 
	linux-security-module <linux-security-module@vger.kernel.org>, linux-integrity@vger.kernel.org, 
	David Miller <davem@davemloft.net>, Steffen Klassert <steffen.klassert@secunet.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=mail header.b=auHBa5AE;       spf=pass
 (google.com: domain of jason@zx2c4.com designates 192.95.5.64 as permitted
 sender) smtp.mailfrom=Jason@zx2c4.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zx2c4.com
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

On Tue, Jun 16, 2020 at 12:54 PM Joe Perches <joe@perches.com> wrote:
>
> On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
> >  v4:
> >   - Break out the memzero_explicit() change as suggested by Dan Carpenter
> >     so that it can be backported to stable.
> >   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
> >     now as there can be a bit more discussion on what is best. It will be
> >     introduced as a separate patch later on after this one is merged.
>
> To this larger audience and last week without reply:
> https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
>
> Are there _any_ fastpath uses of kfree or vfree?

The networking stack has various places where there will be a quick
kmalloc followed by a kfree for an incoming or outgoing packet. One
place that comes to mind would be esp_alloc_tmp, which does a quick
allocation of some temporary kmalloc memory, processes some packet
things inside of that, and then frees it, sometimes in the same
function, and sometimes later in an async callback. I don't know how
"fastpath" you consider this, but usually packet processing is
something people want to do with minimal overhead, considering how
fast NICs are these days.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9rCD1KJNguthAhZ%2BOAVZTpBwEvGRLRV0tvQjBaEYG1bHQ%40mail.gmail.com.
