Return-Path: <kasan-dev+bncBCM2HQW3QYHRBSWLUX3QKGQEWM33WVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D5B61FC2D6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 02:37:31 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id u110sf311013uau.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592354250; cv=pass;
        d=google.com; s=arc-20160816;
        b=PVZEw4sw7nhutv1gcVvVX7ZEEf27ZOGPNEAdZfhq1PowtAZtFidxgAI2VFToSRPhC5
         GZBNZ4jUzZ+91WzSvgTYo+HX5G/8EUgaV4FEh8tS9ZbKovFUujb4mn5Ki0ehRDwxVwPP
         SBxOzqOGv9tE9gVMGohpjSMATC3WJ3WLn4cAUnKW4yOXOns1Xjr4D7R8+sFMHIVbBQXe
         In0KkMjDJI5r7lUaZTVSzOrI4fJWVyT04KG5M45bJRaOlxFLYX3dqGVsSnKQ/SgYS8PA
         wi4i7cVcSrukJWlkr5Od4YcD736K3Q6GjOgNcx6rdwflLnJcn1JNRq4odckP8gZr+PN0
         Uf4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:to:from:date:sender
         :dkim-signature;
        bh=2OLK5dJCRW2f/Z0NmPqcN0piVH5uKcOyCCNCBmX49fY=;
        b=gPPhLkP8lLd+0QjYaOouRk7L8sqmIbujJNxfpoKaWX+SXN6gk4gi5WRaveMoCWccH2
         ObFQgmrEnej2i9+RlEPRhae794fps3+f1oHb7OUS4EEYGXtwszsPPXI8uVaieSwQiWBy
         KAajiH1Iqgn5qDGlxcmDqctrjmIGVPPkgscX7yOT26LIcCWXfjqOlA3iu/hp8DGv7iZP
         RI9ykWHBWm11iqvGNOvQFWadRYW+/0IuC4j8JkNJcQtlU9kHbr1bOPmSPTcEsxP93hXb
         UyVBUCHr2uq6Ceeu5qce4IW561V3LH2lJ3MmbOwWFscf8S3E4OJLXCfx3mL91HdKIUP9
         kNRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n3JyTVpY;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2OLK5dJCRW2f/Z0NmPqcN0piVH5uKcOyCCNCBmX49fY=;
        b=jdsZati05Ww9nR/CE2WfQ5MIKKS9btsVm6pLKB08A+Up5N1bJj9jNk5XRtfYoIgsTH
         fh1Fu0O+lNo7radPcrP3nWaAjsL2qZCalrhB+Uvs5IDPUlFMo3zDFbyIzwBsK0rFYn46
         SXja0Xm0a/gNmzlzV3mxlGW3xGsHoYrWNDisiZAeweVmqeIhg3rcfnrnvaZXk6zZwgKw
         4kpu5o1tGN9QLWdvrjCyB8LJP+5JwjvUOmJ6qICvX3tKwDSr5FnuPZ/LNgQHbIo14Fde
         g42boA3sM+6CNa0KlAUL3emD0jXzqjF0HL0ps2dwvGyfSed8V8MgTkfUNn87yk8eICyw
         8rRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2OLK5dJCRW2f/Z0NmPqcN0piVH5uKcOyCCNCBmX49fY=;
        b=QR7gjLwjZlUCpA8+4UrKOj1M7COH33IPUwe8zZ5dNQa1UJXxu+nkkorBsrMocoxjxN
         z8qhXICxk9fro3hFwN7Xu/+h+uNIPL74igSMN8/j6dN00xdzBYVg3n3XTbd6ypXywaWb
         Z9G7tuGiMEDjD/p3lSHt99toeUJwYKMb3Xf3oUWOjHJY0M7l03DsVakg1ZI0YaHTDXqb
         m6uHJWqDpnjpGP8zisR2XFyZga8rDT2wztyuMiSB6nFqP227Ep/3qqTWdO9omibVO5s8
         fI6tV/8JKf7kvQI7NC+ON0qmNGJYtQNIq9GULY58ABm68xh+bcqYZ5YY7JBfWLNZc9ub
         kD7A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nBxvYykVahI2/woRiAk77kp3UjnCefhWyxmM7LP8KTSSpqrrs
	RT9/V73kWkvlJENwBpX/DXY=
X-Google-Smtp-Source: ABdhPJzyWA8RdyA3JhT5+XBesIUCiCDPfMjm1z2+/ngPx0cwwNKM3SCwutUgQyCfyv0y1HJOm/ptrw==
X-Received: by 2002:ab0:6e8e:: with SMTP id b14mr4742204uav.0.1592354250353;
        Tue, 16 Jun 2020 17:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f993:: with SMTP id b19ls74579vsq.5.gmail; Tue, 16 Jun
 2020 17:37:30 -0700 (PDT)
X-Received: by 2002:a67:b741:: with SMTP id l1mr3905610vsh.180.1592354249920;
        Tue, 16 Jun 2020 17:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592354249; cv=none;
        d=google.com; s=arc-20160816;
        b=dx98jqznpB79Vf7SaUXdd+pytXAJ5eLxHfvPin/oOzQtkMk8Lq8cK+0ojtNQsQGxF4
         FnnSNFS7zkirNwn5bXruLoeXrh6z0P7LMgwf11Ibq8vXu2toguSMlk8AVC9X8RrnSQYf
         I84GZPuRzn+Rsy4T0OIbO01OCex7X5lAHZh380LiN9pwoeet5UVr7iYFG1xP23Z0hMI2
         njDZDeHaEms9lfqgvv0E1yOr2h6lceiEC804ORdB3bHSlLkDyVuWr1gWWfrbGgyNBJOS
         jZqtyj/GAcsf7TPCHqoO5bjLRoTdD10lb1cj8PZxduVinHNMSXIug0wcaQl7R8hVEGHf
         lqAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:date:dkim-signature;
        bh=wFQoXTSBvbEH49Ty46ov9C8/Nsm6g8zmno6k8zfkw2E=;
        b=MwupdIDvO6YYyk7CpubKj55ZR+ybQ4Hvgr31uvsmf2S6gZb5Sff6j4cvv8jmhDVUom
         K6qWmx7l2AfAldio/kTzi6gJs6yCqMaDuadw5O7WNbglFgi8S3VROb1AmXntfNI54Qez
         zYxNPobfRapg7l2D1D8nmzdy0q6pavbxTubA8Mv8w7vTr4KqaNzaNgpFlPVhhc939gAz
         zB8nLAR+S52U4vcOyqKxWpdXylYuoMPHO1dLQBG1U/Etb8vxawLBjCtXoZ8G16N4muQV
         IxUrA5dRiNo1WlMC90OJBXT8qd4kkWtEX/Vm+V45uvxPQA+4Nr0bESsU70kGOSwyeif8
         cUxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=n3JyTVpY;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id e10si232225vkp.4.2020.06.16.17.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Jun 2020 17:37:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlM4l-0006AH-5o; Wed, 17 Jun 2020 00:37:11 +0000
Date: Tue, 16 Jun 2020 17:37:11 -0700
From: Matthew Wilcox <willy@infradead.org>
To: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200617003711.GD8681@bombadil.infradead.org>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616230130.GJ27795@twin.jikos.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=n3JyTVpY;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Wed, Jun 17, 2020 at 01:01:30AM +0200, David Sterba wrote:
> On Tue, Jun 16, 2020 at 11:53:50AM -0700, Joe Perches wrote:
> > On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
> > >  v4:
> > >   - Break out the memzero_explicit() change as suggested by Dan Carpenter
> > >     so that it can be backported to stable.
> > >   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
> > >     now as there can be a bit more discussion on what is best. It will be
> > >     introduced as a separate patch later on after this one is merged.
> > 
> > To this larger audience and last week without reply:
> > https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/
> > 
> > Are there _any_ fastpath uses of kfree or vfree?
> 
> I'd consider kfree performance critical for cases where it is called
> under locks. If possible the kfree is moved outside of the critical
> section, but we have rbtrees or lists that get deleted under locks and
> restructuring the code to do eg. splice and free it outside of the lock
> is not always possible.

Not just performance critical, but correctness critical.  Since kvfree()
may allocate from the vmalloc allocator, I really think that kvfree()
should assert that it's !in_atomic().  Otherwise we can get into trouble
if we end up calling vfree() and have to take the mutex.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617003711.GD8681%40bombadil.infradead.org.
