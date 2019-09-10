Return-Path: <kasan-dev+bncBDVIHK4E4ILBBWG23XVQKGQEZRJ23QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id B71E2AE6FD
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 11:31:04 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id d7sf9967103edv.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 02:31:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568107864; cv=pass;
        d=google.com; s=arc-20160816;
        b=jr/XgmJULgpqq+N1QoN6DD3UVokAXikFdE7eN6HchEEFAyd0Tb5MG1j6bHA7gK3OSE
         wKIR1WwnPC+u7dan2MKnbQoq63iQGHg+lrDguANjiO5uYDJXt1gjB9uGGgvChRpP9Vot
         lqjELIsdTsHEZT5OAH+vqufLeRjAHEM1BUmRrFBiT6aEHcziep+1nNhcM774GQ3ZKmUY
         25KbuqvSWzvo3OHQDCuzJ/3Ud/x3TaoglOd7y9SLKcyQ2pycxoBFHCKznr4W8RxRr6yZ
         J5Gm3qpSdyg5PjAJt/O1jqUd0lzEPzIhgLsFzzs7lmQVIZo9DW8F41bpxdWLQKJP6Mhd
         DGgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fBgSzFA1nmMo5UVc1RANY449I5GFekdZZInl9uO5ysk=;
        b=FLdlHlnmLxL1H/wSuyz2g4TmOHG2CjRwPxSpgTSdVAVEx7Gb1mhKDpWFFM/VK+nA9p
         vxd0l4Stadab7mmmDY/40KDSDNHU/PPeMgZEiDdwigMEQANyD8rZAXKI2qpWWo3P7+iN
         e2SKWFKtcY0RKH8lVf8CqJ4sejs01/jQjeV406DDqyVzOZPtpw5TqMg/Y5UI7tbMGTgX
         DZoZMs+n/7dc+bU2YycU/Pg1nsdXrxPAOK5M9cswZyhEMzCX50jfeF5kW/fFQEVD7e90
         lHZR0PXRzH1tfVxW8laJ+IvbbsMSjFCF+qEihqfwpN28rQdDl4AUlTZouds06c1EiRky
         3B0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=SSNNjgPQ;
       spf=neutral (google.com: 2a00:1450:4864:20::543 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fBgSzFA1nmMo5UVc1RANY449I5GFekdZZInl9uO5ysk=;
        b=SDYC8YELtbPeU3JDK56ZyieoTx6C/gyR84cAEuu34W8TetGnzNHMfLqskhrAN3/nHG
         aQMvEy4BArYwHG1j1W3+vZdbw6lNuCiGr975EaEImXgodOZf5PTQRmYsmwkQHMpc98gL
         mtjYM0TSnPSYRwGHyRMlYAMTVT6C1G7buUMAkGy2CxuU66B92kuFGR3iKjta+QCi5KoL
         yYg5CYZT3xRY5b8ZDbX+yW8ef7fwYCFaltiIfZTATtjdlCiml5cEXTm74zU+S+L6X7s5
         65mjT1+IR84lwQbx+INByyZ+UY8QdWTFDUCodCbJ7ga662XPka5apLes3rsrVlyZKzLh
         Qj3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fBgSzFA1nmMo5UVc1RANY449I5GFekdZZInl9uO5ysk=;
        b=ITeH+vsPXzLOftXbKBeuMeb5gGUVCQ/QN/Pc0njfR/tYs/d+vetO/VgWS7AsyO+xrF
         CN+1ed8qbtCyS345WNS5nRmkBLwCVZe0PbGPx3lGYPBybbiApzLfQGxo5FqF0uNdGXeH
         VBh5nrzQDWFhGVs9tLQCG9ZKqYZDmSIMkMi6rVvISalxWgL5G4IS0R4I9QhCeu+9t0rx
         LYqcXDl+4JkpM3PMlDx/x6ivYzKsknC3CYfwlIKHod18Mc5tBMQGiddPzrboe8pQ0q9S
         xuzWFPAkGFE5Ax3dpWDOz76RW1I45a9dX71C+6ut/q1NpIXJrThFR95MBP6+ADjMAc9g
         FRCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVItmL8NzjmVLuaoFic3+xmZ56Nscamj+udhC7mUJVb+YMOiESf
	Qi1E2y47tpICgiHCDMx6rvM=
X-Google-Smtp-Source: APXvYqzvOD0BEDb1OJoekMutP16dytJdbD2k0TDs0Xgpk0mTj78oPbleAt9bP8irC7s4IkyzZhHwyg==
X-Received: by 2002:a17:906:fad4:: with SMTP id lu20mr23077865ejb.87.1568107864435;
        Tue, 10 Sep 2019 02:31:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:c28a:: with SMTP id o10ls4432092edf.8.gmail; Tue, 10 Sep
 2019 02:31:04 -0700 (PDT)
X-Received: by 2002:a50:9e08:: with SMTP id z8mr29955257ede.305.1568107864077;
        Tue, 10 Sep 2019 02:31:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568107864; cv=none;
        d=google.com; s=arc-20160816;
        b=Fi3F7UvzYL7KfL/uF6kpUw4pT9LFVpheBAO413H1SV9hUtCszONeq1L/PVDB0nhfHO
         zhLRWAxlJvbAGJfZW2hnvsUgpdYfiKQS75lSqZaXmgEPTNACWILeMDYdNGiwvtnXcWBI
         FRXm6tZflKmhEctMJ8wNmXBN1cSQXwGdXUYa0Jpb0dg8U7RY5UhTD130PgHtuVDFK0fM
         aG/YlRFZn9Ka2pefrqXWyyP048fLndiRebgjlHshu6KxIekJCSITyhgIMokx1zWXQBPS
         tIbDVD9RV/axQkkQm4zMpAwbi9XIAqRYjgpCCD9kHqfcE+Tynu3T1hmWwZTzAcPvk0Gs
         Zzqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=nPUEYX1NKslohD2E+roi3GND2/I3OUXfvQ3XAcK+/GA=;
        b=H6aH6DfFpT1GVGOQnSZ7F/DUTcCGB+by2XTD7Qxmsoskg6MvC/JCJL6nVWACJZR0pp
         IMfkHLnRCAMiKzpvpMacLKK/Vi2S4/Tv3PsK/4VNuNUAbFBPIoatUNGXz4TpuksIyElz
         jvLTcSbR1DUVjSsil/0Og5qb0pcRZG4LWcQLHg0L57wXv9oCtEewqHOQU4opBqkArGtz
         ajbGpDAtXPyvN3wEJ100ydnZbHgKkOouShnxtUEXElOQ1A7PIDNwkvKJC+vSxnYdAkt4
         ePcR3yT82BnrNT4iD64G434B3OnGMZNvgl30N5X90ZUJu0kx4Tw/ngEC3/lSEwuzWLN/
         DK4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=SSNNjgPQ;
       spf=neutral (google.com: 2a00:1450:4864:20::543 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id r20si327339edp.3.2019.09.10.02.31.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Sep 2019 02:31:04 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::543 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id z9so16382921edq.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Sep 2019 02:31:04 -0700 (PDT)
X-Received: by 2002:a17:906:4f04:: with SMTP id t4mr23891798eju.190.1568107863856;
        Tue, 10 Sep 2019 02:31:03 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id u27sm3463898edb.48.2019.09.10.02.31.03
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Sep 2019 02:31:03 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id 9F3511009F6; Tue, 10 Sep 2019 12:31:03 +0300 (+03)
Date: Tue, 10 Sep 2019 12:31:03 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: David Hildenbrand <david@redhat.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Martin Schwidefsky <schwidefsky@de.ibm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
	Michal Hocko <mhocko@kernel.org>, Qian Cai <cai@lca.pw>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
Subject: Re: [PATCH v2 1/2] mm/page_ext: support to record the last stack of
 page
Message-ID: <20190910093103.4cmqk4semlhgpmle@box.shutemov.name>
References: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
 <36b5a8e0-2783-4c0e-4fc7-78ea652ba475@redhat.com>
 <1568077669.24886.3.camel@mtksdccf07>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1568077669.24886.3.camel@mtksdccf07>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=SSNNjgPQ;       spf=neutral (google.com: 2a00:1450:4864:20::543 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Tue, Sep 10, 2019 at 09:07:49AM +0800, Walter Wu wrote:
> On Mon, 2019-09-09 at 12:57 +0200, David Hildenbrand wrote:
> > On 09.09.19 10:53, Walter Wu wrote:
> > > KASAN will record last stack of page in order to help programmer
> > > to see memory corruption caused by page.
> > > 
> > > What is difference between page_owner and our patch?
> > > page_owner records alloc stack of page, but our patch is to record
> > > last stack(it may be alloc or free stack of page).
> > > 
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > ---
> > >  mm/page_ext.c | 3 +++
> > >  1 file changed, 3 insertions(+)
> > > 
> > > diff --git a/mm/page_ext.c b/mm/page_ext.c
> > > index 5f5769c7db3b..7ca33dcd9ffa 100644
> > > --- a/mm/page_ext.c
> > > +++ b/mm/page_ext.c
> > > @@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
> > >  #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
> > >  	&page_idle_ops,
> > >  #endif
> > > +#ifdef CONFIG_KASAN
> > > +	&page_stack_ops,
> > > +#endif
> > >  };
> > >  
> > >  static unsigned long total_usage;
> > > 
> > 
> > Are you sure this patch compiles?
> > 
> This is patchsets, it need another patch2.
> We have verified it by running KASAN UT on Qemu.

Any patchset must be bisectable: do not break anything in the middle of
patchset.

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190910093103.4cmqk4semlhgpmle%40box.shutemov.name.
