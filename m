Return-Path: <kasan-dev+bncBCB33Y62S4NBBSF3YKXQMGQE35SVLIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-f58.google.com (mail-oa1-f58.google.com [209.85.160.58])
	by mail.lfdr.de (Postfix) with ESMTPS id CB310879B48
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 19:24:09 +0100 (CET)
Received: by mail-oa1-f58.google.com with SMTP id 586e51a60fabf-2218da55d89sf5861982fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 11:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710267848; cv=pass;
        d=google.com; s=arc-20160816;
        b=oa2UoP1vHO6erJeiDBTIcNRBrgRiE4ceBrSfSvptzIttg0TvBPR+0O+JAq87KGLRDm
         FAfdmWqKLFRG/4jn7hZxPs418l9uYyyP/85AODFo6OmwedOcSo+vgRIhzrFE9AzQA98w
         E7sa9OFr9nhA7IXFWIy2VxGpqge0UO8dBiUDquEDB7AuaN9KTy3HWbB2KCYWD/hACqpf
         1H8OtHbGyhWy3AvjNcFdIPm83jmvMxzrD0b+LBLL2W01YEkB1QoYc0OrGUNJUZooBnBE
         7ogZ5jNLQAa8IkOsOhC8R1oeOiKLPZeHNONHZ/FkzXLqd5RSJLgMQh4Qyl0787I/HCBx
         +sVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=qUikpoCW0nNJupRA8X8uHFg4nDGmlUJ4b+rVmSWZUdA=;
        fh=WkBGTnKpIUyXbtUX8hAPCcG6WPrgfzvnoEMHIcT/TNA=;
        b=SpOJirHrpKF1SlBzH2ZM2cuFrCj4g0wNu9MgYg8NxZK4NR0tkEajIw/HHs1ysDVFZh
         nYODkJM748Hx9PCwFJP4D7RnR91Mvi9icguTyxaCXIOZ7Tu9WdzCikSZyrlAPnlqYkRq
         8pvyQFqxy61bH+s7OsQiK1cybeYjW6JRjHjmKJWjDmltEMuvYVn9ELRBVXo8wwbRmWdH
         l4bP0vWMIurG4JWp1c0DUIhH3BTXcoeTHa9QF0hfaq8qGVs94fQGLKsvRO1qwoJ8jXef
         x4T3/wCnKTB/xhdWC0uQt8GSeih242wvCBQ8aULsvQWj4HmUutMrIghOI8lhcJS4/6EW
         um4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=OTp6Uakl;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710267848; x=1710872648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qUikpoCW0nNJupRA8X8uHFg4nDGmlUJ4b+rVmSWZUdA=;
        b=vmzktu2fzzfttb8z3lFhiULayh22g/qTil5DWNqIv4qYLOh0OrMKEvhKPj7RPwvZGl
         K60IcUkW+NVwFHvKvPcMsc9u1MrZk+suDoW8dC1zcxOr6HTk32zCJSWXZ3CDXAOVd/El
         5ShGBGX2dfjFnmHgh6NebvBuihKT0eexRc1KF86uv5j3AT3U9uGCgXoVhNtiZZhSijy0
         XbEZ4D4Jk9YxZxywhSWnBKJFtM4RS8CDR5ruhujiyJwef9v8V1289zirgkWJ4356qUD3
         BjBxi6RDpuxrdE0/7WeYeH+K7miMjET+4rAtoAaLwNDRSs2mszJDaWbEOQwDSG69PUPI
         kgDg==
X-Forwarded-Encrypted: i=2; AJvYcCV6vILF5BS+fh9+wgeyLywHhANgR0grobghJvDv+90GCGtPpGxH2kJzvvfhq3lzjO25Gd8P+qI2bbbbtPFsCsSgqhdU1yA44A==
X-Gm-Message-State: AOJu0YxDG52by8CPAuYhjFtovRAhbO0kIiD6iiStmXDfyWqbOWczRmsH
	gFhxcT+71eE3Ald7znndumogCnnYo56Il6JClixFNFkBF/SCvijD
X-Google-Smtp-Source: AGHT+IEZBJiNTO4eXZY9q+2GFYj5WkBS2NClITQzMM2wlSy7XmgBaiQ0Y9PzsQRJBReSyr81ek9K2Q==
X-Received: by 2002:a05:6870:700c:b0:221:dcec:fb7b with SMTP id u12-20020a056870700c00b00221dcecfb7bmr8363306oae.6.1710267848455;
        Tue, 12 Mar 2024 11:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4997:b0:220:c925:13d0 with SMTP id
 ho23-20020a056870499700b00220c92513d0ls1752700oab.0.-pod-prod-06-us; Tue, 12
 Mar 2024 11:24:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPjKqyhFzDMlNCi7UNy9RfjuLP48WFW+qBBAQiyuX26ldMBECQHNYqMw43L9usoAa0tkVI3+YJE/iji5ecHrNdLkhtdMGmIY+OLA==
X-Received: by 2002:a05:6871:590:b0:220:9f0a:667e with SMTP id u16-20020a056871059000b002209f0a667emr9199358oan.38.1710267847735;
        Tue, 12 Mar 2024 11:24:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710267847; cv=none;
        d=google.com; s=arc-20160816;
        b=BH46d2ovna+yPyMh2Ra650ZFG7+Frcrc6bl+wV2DnFhVDfZaVN0i4Fq8kOCVE6x1eZ
         04D/Oz0FHYjD0nJMC9JJ2tGq6xWdup2UwYqfbU6qY7yWoYEs63rq9wLk7ztiKIEYcuml
         QFFSD/DDSjF9cYvxd1uPlOUTfpUjOThvqlWicXBodNvAjXGEGfzt4sQSv6RXEafRGg0k
         OFJmPoh0Xe9BDu6OLuWebhKpoPangJUTaQuL0iXOzQbD5qSjX3V8HghLK5S56cjbG9Rf
         LwiOMYdz2vpYyiDE3xB75qOSnJh8owYJqVzwC1ZCYHihwgUTc/cjlSiqG2VAoEWCCMml
         BeWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xm7GbgXJn9YwnZvlLSry0HH3FBwrqzxic0mWxiDob2w=;
        fh=bn4TuujawAxSSVHDBNpafHGwExxtearkDlAwhFlJ/jw=;
        b=JiyX5Ha4epqm82wJ/e4SKlnQuJIGEtC0cJZam3/nNU4DRHXateuHu8PJm1V02qA4Cz
         FLAEuI2c1i+zJ/nE/xGouR+CO/rHdHWceey3RYJBTundBe4Lh2jUVY4VsaYeGGlAKW9W
         SAQ76FAMyb4kL99UpuaMs4CAOijzO4kebrCCY28FFE++gfnTslbnnLPVOl7GuvTlCw+r
         zashZJ0a1TKoozd51CXX8Jyc/ynoxjRY3Q0sjV6hJqZ+LfuI89JGiBLcBKRP9PliJsfZ
         LItLmf04oTBxv0vULIzp+6n522TQGiMF6ZPdvMv2UWebctdyyrBnl0kJaKjoCVOOZJ83
         QnHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=OTp6Uakl;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id n31-20020a056870241f00b00221bb59c450si872909oap.5.2024.03.12.11.24.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Mar 2024 11:24:07 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from mcgrof by bombadil.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rk6mv-000000076Ob-0eEr;
	Tue, 12 Mar 2024 18:23:45 +0000
Date: Tue, 12 Mar 2024 11:23:45 -0700
From: Luis Chamberlain <mcgrof@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, masahiroy@kernel.org, nathan@kernel.org,
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
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
Subject: Re: [PATCH v4 13/36] lib: prevent module unloading if memory is not
 freed
Message-ID: <ZfCdsbPgiARPHUkw@bombadil.infradead.org>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-14-surenb@google.com>
 <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
Sender: Luis Chamberlain <mcgrof@infradead.org>
X-Original-Sender: mcgrof@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=OTp6Uakl;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=mcgrof@infradead.org;       dmarc=fail (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, Feb 26, 2024 at 05:58:40PM +0100, Vlastimil Babka wrote:
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > Skip freeing module's data section if there are non-zero allocation tags
> > because otherwise, once these allocations are freed, the access to their
> > code tag would cause UAF.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> 
> I know that module unloading was never considered really supported etc.

If its not supported then we should not have it on modules. Module
loading and unloading should just work, otherwise then this should not
work with modules and leave them in a zombie state.

  Luis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfCdsbPgiARPHUkw%40bombadil.infradead.org.
