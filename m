Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHVJYCRAMGQEMKL737A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 94FBA6F382D
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 21:35:59 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-50bcaaeaec0sf710517a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 12:35:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682969759; cv=pass;
        d=google.com; s=arc-20160816;
        b=kwvpXy96C0I5064pc8BU8ulyHHhIRW6cK0qadvVsGR7FS/oI/zWf1tclTWuRspexDZ
         ilaP1PRSrsvx5qJTW2aQoEnNQVv2Khx215Vu+PENIJuMcBr+QU55Ma19bI6+lOkFETtD
         GFokUsj2SeLW90VJr0WnMsus4Hw5ncpcfb8nUYJo5O57IMYslFLQxEHthOVke59qmn93
         J4/knisBjEWPQoSsTnbUL3qEYF1Osyh0/f0kJl7jQMIKwWXHRJ4p8HzcaisG+qhthhFv
         WMT1Jll5iRYHdQH+XO/C4Js+ha4wFqCvrUVqA+ogSJokIlc1tf3UodtNLHmY9q0Uy/JC
         OmnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:to:from:date:sender
         :dkim-signature;
        bh=4FoXH1SFAa69ykIfbySRL+KZiIRzVyyforMjii04MiY=;
        b=MP/4Zprh4zkx0ToywXpCw1eROFgPxyuyYRva42CFpPhmX2Vwa/I+nPWLzIEyTNkbO+
         9/Q5X7c5xqNOjQwzZryJIlD8WfYJ7yz2l/MARpJomySp2uKOKRNMeMo811jzG+Y+KsFc
         4Yyyky8DFDaVkTfWZLOEgEt58j3LQ7mbXjp0fCiSi0oieHUu5S397sbygYUqvb1mbsDi
         CsePsDJJ6daUZVDVIjf8WzcZNjhQMKm++YiFY/x2GOEYwupDQahU4aaf343fC5cqcqmN
         EEYjoQeIDWlyUq/yauwdXZtiOeFx3T2vB67wLqqYqC4GGuUXbjbNPVRsaOLNvhdRFsPd
         AfTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uotwq971;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682969759; x=1685561759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4FoXH1SFAa69ykIfbySRL+KZiIRzVyyforMjii04MiY=;
        b=XwzcX/ZCs+gx3X7SQMjOIUVu529XytAe6CKsUQMjGGcZWfwFWZfdhfyrOIU02eEKUo
         36gcnPjvZlcAGkEx8d9/cdcF7HFTIQU4xgSNzauDjcHEMGmUscniWqpu6PUCt8IVat90
         KMdc85zH29nsgHaHeakTnIAyNAxIwejUaXcRozgKoIn8JekPp9q55t5J4kYxNm/QR+95
         yIaYfe4EpioMEIe4oVD1Md9ZjLNZrH2D7MgcCQ2uftRu9D2T99LjAJAsSZr8Fjy6GvrN
         qd50NMW0WV0UM8KMEeJWXZK62gJZSGmtHz7Qxu50Oalqln09+o2C9/EKe56u8qhVNpxa
         lDOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682969759; x=1685561759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4FoXH1SFAa69ykIfbySRL+KZiIRzVyyforMjii04MiY=;
        b=dkCa3+x9AGTv3s8POFA1yyrJjWCRfpPJ/bcN0WiHNQX0xuQVEgHO+RrdihrFAVhJ7Z
         icFo9ft+W0hNsmnvihjqgYXo3WU4Q/EmwfOPt/1sYC+hI0Bamw8WJunGaFFkSliZJxDC
         cOEoIdUIyTOmmXfswaSzSHc745HLXO8VKCFiqMxJHQctZxueCv5qlsyZU+u70Yv/bLc6
         UnDOF4I+PC+uSfFRW1QApMJBa1v9Y9XwB8LKV1zCGKRG5ytyyAz0PUnZh8pv3ixp7iTd
         Ng0lkzZr1yMplLhdd316cJF7BqcpeeyAhPDdb3nXKVvJ5wxQW0AmUowC1D3C6ozmnYJo
         YlNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx/NDDPqQCHawJJsb9CrRIG9QP7z7kaPzF4DAcRcXgmWXOPJQGH
	hdnmwqkxTV7qG/NJbHrqx7s=
X-Google-Smtp-Source: ACHHUZ6Sh7oUomgreaEyRdt9b9kTkje7b5jQX1lgE1TKmBkzBozzotXehKNHtpJTQG9wIFQuIdwLuA==
X-Received: by 2002:a50:d781:0:b0:504:a1a7:6916 with SMTP id w1-20020a50d781000000b00504a1a76916mr3195112edi.0.1682969758866;
        Mon, 01 May 2023 12:35:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:190e:b0:50b:cc92:508c with SMTP id
 e14-20020a056402190e00b0050bcc92508cls847748edz.3.-pod-prod-gmail; Mon, 01
 May 2023 12:35:57 -0700 (PDT)
X-Received: by 2002:aa7:c3d9:0:b0:4fe:19cb:4788 with SMTP id l25-20020aa7c3d9000000b004fe19cb4788mr6052910edr.42.1682969757625;
        Mon, 01 May 2023 12:35:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682969757; cv=none;
        d=google.com; s=arc-20160816;
        b=EQudXQ+mSF1nHaDHrygQd/exdwWgccVAmbwgZZy7S/l/GWG+FT4GrrDte0i6uiLW3F
         jPmtrV+W6OxMh3gDg+M+w1AUyIg71MRxhjPqO/6zgzYcnfALGY1XdlbdoEb799UyPNqn
         LjP76kIQO7kz6/AiCE0uktvxISxcNGxWH2SY1LtduRx2VXa7Blj6eGuDwfvZJva2JcW5
         ktVp5UbV8bcZ5j3QAyeVEsxLhkLJqXxni0L3DfatTXlKA6NcQ4y6uyyConPD3p6gTRLV
         W++TpPagFbrkTxnDv0ZWsFxkpVwLO6Zog7yv1o5VLSJFv05NAycVa65DzZZrGuWzYloK
         HZrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:dkim-signature:date;
        bh=hpWnoWbnH7XHW07GL5HN1fHIxDy9SUudHHmRHAQgRBM=;
        b=FlMSXvZ6M6S8T/dCXyeDjE2BHnupgGWbU9CA/I7lKiPXH/rexjv28clrnhyFcafawG
         atiKNFQzPtK+k1F7/YI+Oen3RlZWtepRvXEr62ZrYZcvjtd4DxskowcBR22DybqflBfV
         mWDzvWiL9VxrMz6efT0H2X3Da9RxkgoVpEVE8ADLBpIA3T0fns3HGOmI/5cauZPOefpw
         BCEtaRX967NA8B5kIYrWkYem9vaj4Bvj+vtIYv+rVFX3Aw1JhzN7h3A3iAZSizklGXXF
         5vYbAqCkwQ2bbf6UO97OZOpzszwAQOC6P/R7fDb5Gth11/8X+9yaWzIOMylf41j7Zmkt
         vAyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uotwq971;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-48.mta1.migadu.com (out-48.mta1.migadu.com. [2001:41d0:203:375::30])
        by gmr-mx.google.com with ESMTPS id fi27-20020a056402551b00b0050b87b70258si273891edb.0.2023.05.01.12.35.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 12:35:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::30 as permitted sender) client-ip=2001:41d0:203:375::30;
Date: Mon, 1 May 2023 15:35:43 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?utf-8?B?VHLDr8K/wr1ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <ZFAUj+Q+hP7cWs4w@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=uotwq971;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::30 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 01, 2023 at 11:13:15AM -0700, Davidlohr Bueso wrote:
> On Mon, 01 May 2023, Suren Baghdasaryan wrote:
> 
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > Previously, string_get_size() outputted a space between the number and
> > the units, i.e.
> >  9.88 MiB
> > 
> > This changes it to
> >  9.88MiB
> > 
> > which allows it to be parsed correctly by the 'sort -h' command.
> 
> Wouldn't this break users that already parse it the current way?

It's not impossible - but it's not used in very many places and we
wouldn't be printing in human-readable units if it was meant to be
parsed - it's mainly used for debug output currently.

If someone raises a specific objection we'll do something different,
otherwise I think standardizing on what userspace tooling already parses
is a good idea.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFAUj%2BQ%2BhP7cWs4w%40moria.home.lan.
