Return-Path: <kasan-dev+bncBC5I5WEMW4JBB3E47HBAMGQE55KYKKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C2103AEB0AC
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 09:55:32 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3a5058f9ef4sf879642f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 00:55:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751010926; cv=pass;
        d=google.com; s=arc-20240605;
        b=PQVJxfVfAdGNhaQ58hxVcZJEaQ0Xca05NYcNhtv4CW7hbFBbI/QsN7PtuMmKCFMdYS
         +Z4LtQ9IA0rDcK1Uz6ZXZesU/ixGPY4Zd5n6qeKrfy3NIVMpkb/jFH+zFbzCQB7CCH1F
         mr6Yfw9y3soS/KJX4WkbxRhWnVTfMQL9gQAvdJJIRtkSSRC2PRO+D+YDqSPjnpY+QE1L
         S9Z8mdrgpKOaGFeQTTPODhSgVrF5bveR1h655XPAm1yjg4Slc+XxpV94H1amQe3WLabV
         X/ikgPGegoC5vPEh5/7o2qFRZWz+b6hZiDc6eko15GOyDKyT9JPeuRfr0mR+zbFX1LB1
         QthQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tEuSUQNJK+3/7zTgaRJBSvsAfws8N3EYewtd+6zUq2I=;
        fh=CSCy1FSzlgGMBFwzMMRsDaKaFumpMAcLqT9OxjOxn94=;
        b=A+JKhcuxOXYb4wRwkOcZODDNGir83lDWHB9/mXvzPElcHOCQYKuJlyEiywUdMjM+NQ
         XOo4CnMtl+F9gzhprwhgN8cPYdxWiviHJtr1mr0SFvgoriPDLNH5ta8Y/AbT6zz3U6Uo
         F3Cz7CxVlienWONdMzaDZFyDnnrBFlDzWnx+5iqM/em+VguSzA1QMUZJ2v88I6p+2wjR
         ai7Nk/ega++uIo6hFOGlEtPTcgi+K+1LTyGWlC2RF0GJ8xAPU9kJr/yvmG6Onx5DC9jr
         qIRMwiEHcqXwoMDXrtDuzlxhbSXJpBZG/sSMtXg1YcJ2foF7u96W/29SkodKhUf7F5Dc
         IBJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FbbeNE/T";
       dkim=neutral (no key) header.i=@suse.cz header.b=Kty7AgHZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2fJ8jZ9U;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751010926; x=1751615726; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tEuSUQNJK+3/7zTgaRJBSvsAfws8N3EYewtd+6zUq2I=;
        b=kO5QL4OIgsKmb1TQa9kYIsmxCN7OvBDURH5pH4RFOph1wrD6bgoo7IBbXxT2WiMG1Z
         W+R+HfXr/QF3d4HF8LRCjfNMDcCyqQZb12gcvBCzduh/7O5/z9VngPE9vaN8gXAQZ3Ot
         sj7nCb5M3E0HYdyTmQmjzCH4zD8m36OsPWOGj06G9ZhFyfry5SmAYedodcIr2tess4Gh
         WGy4r2rrkLwYcf8zMyfA9qm3pEKG8X7JSw0SHw6xrOPwwXdrlB0i8/ARCd/n8dnzX97X
         M7b1oJf7TtCzeDEp/kBuqo6Iiw/4NhhaRIMny7whdQ9BckhCu5rs5G1TPfsT1a7pBBth
         eStA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751010926; x=1751615726;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tEuSUQNJK+3/7zTgaRJBSvsAfws8N3EYewtd+6zUq2I=;
        b=CzCIV90Z1RAd+ZZmI02qT1HQ9h7oleNj/Qk7YuNShKcYmWRiVQh0+uwdRWilmsSUu1
         F7pr3LvMu3vvi154/vSrtnMosT7vjReaJ7LqZEpCGshMn5PFlrJ83c/LQsjbMCB40kx6
         fDZaV/tJZ65KYx7TFZB41c61TS5YBryazqpnwsRx/nmI4f+QbZlWZk08Tgz4BP++DEcd
         tUP6p7ifJreQNjMvxtiRPyCDHkXXSuSH1pxoEu09NnVZ5zrle/fS0ieikRgoj4KcDe+k
         EhFeEPaSJvtFs/vWpeJg8ugbGGwyq8oq77prO3iRTsKCurSDqt9kkf/Lyzbb8ykIfeuQ
         Yy2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX3Y9KtZcXg/pxi1kWaSUG3GQD7P5P0VbF3kdx/k7FmmbbCIlEioF6LXIwNnS+B8YOB4+qmIQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx39ZLBteW8jWwgmUnZtSdXle1iLadAHdgjRBj/yiyu7kChUPT4
	V9ryiGx4VtHJGFyiVa8lgzZdySKKAnII1p6NcnAf+Dq+etvx114hs8Qo
X-Google-Smtp-Source: AGHT+IGBKIWH9tVeWcqD7mP/gbDs8+LvyxJCriUhXnyW+cumjowAfJumZUUJydW696Y03an+NtdtJw==
X-Received: by 2002:a05:6000:2183:b0:3a6:e2d5:f161 with SMTP id ffacd0b85a97d-3a8fda35a9dmr1611821f8f.8.1751010926085;
        Fri, 27 Jun 2025 00:55:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXJuRujeUjq0+vFqS+rsnicoqNNCbgl9zfYbrNzQC5XQ==
Received: by 2002:a05:600c:4f56:b0:43c:ec03:5dc5 with SMTP id
 5b1f17b1804b1-45388ae0358ls10247645e9.2.-pod-prod-01-eu; Fri, 27 Jun 2025
 00:55:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUjjauxJ1eQZMkjUGKeFM5BaSsN720DVbTcx+eJ+NQoEhJzHh/sk07/2lMC6GUQNHZ1pnfVwB1nw0=@googlegroups.com
X-Received: by 2002:a05:600c:190b:b0:44b:eb56:1d48 with SMTP id 5b1f17b1804b1-4538ee4f88cmr22761705e9.4.1751010922234;
        Fri, 27 Jun 2025 00:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751010922; cv=none;
        d=google.com; s=arc-20240605;
        b=l2AXjYybVpiu8rgmuvO9mDhIsCf6v51dlEydvgUiKnS0SG/bIEbhffDaqjiSTk9G99
         LgB8wlqoCDnT/HXfX1Xu9mPOTi+NTXOW5CyVn2uHdJVYQIN5J1g6DDXpMDEg7/7snKlW
         ARhHD9KePz9b8ymgmTXPFqHDsnYUoWo2oV5oWRq54NS8fZHe4HuIp09QDYgfBH+oHypH
         IbKkdt/Ube6s0EacKxiiY4rmrFYZ3whP618ZpgdAtrGTPUZ9E5xomLblPKb38QpI8We1
         BjJZQLqZyZv18h5O8dFC4nvGte8MEn/RNaCK90Ra79wmvF57IRsyYSFcJ75/SzBq1ht4
         OnaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Ptecp9XDD5qXUjm1CHcOI25++V3ZYV625LMiuMqRD10=;
        fh=jWrwS5uQ9ZTKMHQO6ZJAIwd7Wqo6bZlJ6xfNVZrGAt0=;
        b=ETDw4vmoaRiVDf4Q8YyC10sTt77yploBDdN8QTdxFMFss1vvowi5Is3vwTXVUBWG4l
         6TTSUh/NEklFZv/PoryxwzAETdf+C+3b93joJbeaRpHFYYsUYxiIWs0c4smVtzw4P9Cz
         Ze70xdOxwS0W5H3tiWsDlf5JhnbBt0aeh9+oWPtmA8DNIVX8aRWk4lmGyJHLDSHuv6ce
         /Eym1le2ztTx0g2wYNZ6zzSd2tKMNV/b8vjFrVyZK17mOGBRSc6l4Ghn0q31Yer+0Ahp
         uVMan2IQmw3hbHXQ5x9PQHAdzuKG7TuXU5B4OZWBqpBKQF+kBGsFl+IhnJEcgpmq7/fK
         N18w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FbbeNE/T";
       dkim=neutral (no key) header.i=@suse.cz header.b=Kty7AgHZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2fJ8jZ9U;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fcdda2si1903905e9.0.2025.06.27.00.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 Jun 2025 00:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6A5C021174;
	Fri, 27 Jun 2025 07:55:20 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5894713786;
	Fri, 27 Jun 2025 07:55:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IbGcFWhOXmgIUQAAD6G6ig
	(envelope-from <jack@suse.cz>); Fri, 27 Jun 2025 07:55:20 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id D996FA099D; Fri, 27 Jun 2025 09:55:19 +0200 (CEST)
Date: Fri, 27 Jun 2025 09:55:19 +0200
From: Jan Kara <jack@suse.cz>
To: Florian Fainelli <florian.fainelli@broadcom.com>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	linux-kernel@vger.kernel.org, Jan Kiszka <jan.kiszka@siemens.com>, 
	Kieran Bingham <kbingham@kernel.org>, Michael Turquette <mturquette@baylibre.com>, 
	Stephen Boyd <sboyd@kernel.org>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Christoph Lameter <cl@gentwo.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	"Rafael J. Wysocki" <rafael@kernel.org>, Danilo Krummrich <dakr@kernel.org>, 
	Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, 
	John Ogness <john.ogness@linutronix.de>, Sergey Senozhatsky <senozhatsky@chromium.org>, 
	Ulf Hansson <ulf.hansson@linaro.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Luis Chamberlain <mcgrof@kernel.org>, Petr Pavlu <petr.pavlu@suse.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Daniel Gomez <da.gomez@samsung.com>, 
	Kent Overstreet <kent.overstreet@linux.dev>, Anna-Maria Behnsen <anna-maria@linutronix.de>, 
	Frederic Weisbecker <frederic@kernel.org>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, Uladzislau Rezki <urezki@gmail.com>, 
	Matthew Wilcox <willy@infradead.org>, Kuan-Ying Lee <kuan-ying.lee@canonical.com>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Etienne Buira <etienne.buira@free.fr>, 
	Antonio Quartulli <antonio@mandelbit.com>, Illia Ostapyshyn <illia@yshyn.com>, 
	"open list:COMMON CLK FRAMEWORK" <linux-clk@vger.kernel.org>, "open list:PER-CPU MEMORY ALLOCATOR" <linux-mm@kvack.org>, 
	"open list:GENERIC PM DOMAINS" <linux-pm@vger.kernel.org>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MAPLE TREE" <maple-tree@lists.infradead.org>, "open list:MODULE SUPPORT" <linux-modules@vger.kernel.org>, 
	"open list:PROC FILESYSTEM" <linux-fsdevel@vger.kernel.org>
Subject: Re: [PATCH 00/16] MAINTAINERS: Include GDB scripts under their
 relevant subsystems
Message-ID: <iup2plrwgkxlnywm3imd2ctkbqzkckn4t3ho56kq4y4ykgzvbk@cefy6hl7yu6c>
References: <20250625231053.1134589-1-florian.fainelli@broadcom.com>
 <fynmrmsglw4liexcb37ykutf724lh7zbibilcjpysbmvgtkmes@mtjrfkve4av7>
 <c66deb8f-774e-4981-accf-4f507943e08c@broadcom.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c66deb8f-774e-4981-accf-4f507943e08c@broadcom.com>
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCPT_COUNT_TWELVE(0.00)[49];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	TAGGED_RCPT(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[free.fr,gmail.com];
	R_RATELIMIT(0.00)[to_ip_from(RLb9dmf7wrehepajhg9kqn5udf)];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,vger.kernel.org,siemens.com,kernel.org,baylibre.com,gentwo.org,linuxfoundation.org,suse.com,goodmis.org,linutronix.de,chromium.org,linaro.org,gmail.com,google.com,arm.com,linux-foundation.org,samsung.com,linux.dev,zeniv.linux.org.uk,suse.cz,infradead.org,canonical.com,linux.ibm.com,free.fr,mandelbit.com,yshyn.com,kvack.org,googlegroups.com,lists.infradead.org];
	RCVD_COUNT_THREE(0.00)[3];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_TLS_LAST(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Level: 
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="FbbeNE/T";
       dkim=neutral (no key) header.i=@suse.cz header.b=Kty7AgHZ;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=2fJ8jZ9U;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130
 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Thu 26-06-25 09:39:36, Florian Fainelli wrote:
> On 6/26/25 09:17, Liam R. Howlett wrote:
> > * Florian Fainelli <florian.fainelli@broadcom.com> [250625 19:13]:
> > > Linux has a number of very useful GDB scripts under scripts/gdb/linux/*
> > > that provide OS awareness for debuggers and allows for debugging of a
> > > variety of data structures (lists, timers, radix tree, mapletree, etc.)
> > > as well as subsystems (clocks, devices, classes, busses, etc.).
> > > 
> > > These scripts are typically maintained in isolation from the subsystem
> > > that they parse the data structures and symbols of, which can lead to
> > > people playing catch up with fixing bugs or updating the script to work
> > > with updates made to the internal APIs/objects etc. Here are some
> > > recents examples:
> > > 
> > > https://lore.kernel.org/all/20250601055027.3661480-1-tony.ambardar@gmail.com/
> > > https://lore.kernel.org/all/20250619225105.320729-1-florian.fainelli@broadcom.com/
> > > https://lore.kernel.org/all/20250625021020.1056930-1-florian.fainelli@broadcom.com/
> > > 
> > > This patch series is intentionally split such that each subsystem
> > > maintainer can decide whether to accept the extra
> > > review/maintenance/guidance that can be offered when GDB scripts are
> > > being updated or added.
> > 
> > I don't see why you think it was okay to propose this in the way you
> > have gone about it.  Looking at the mailing list, you've been around for
> > a while.
> 
> This should probably have been posted as RFC rather than PATCH, but as I
> indicate in the cover letter this is broken down to allow maintainers like
> yourself to accept/reject
> 
> > 
> > The file you are telling me about seems to be extremely new and I needed
> > to pull akpm/mm-new to discover where it came from.. because you never
> > Cc'ed me on the file you are asking me to own.
> 
> Yes, that file is very new indeed, and my bad for not copying you on it.
> 
> I was not planning on burning an entire day worth of work to transition the
> GDB scripts dumping the interrupt tree away from a radix tree to a maple
> tree. All of which happens with the author of that conversion having
> absolutely no idea that broke anything in the tree because very few people
> know about the Python GDB scripts that Linux has. It is not pleasant to be
> playing catch when it would have take maybe an extra couple hours for
> someone intimately familiar with the maple tree to come up with a suitable
> implementation replacement for mtree_load().
> 
> So having done it felt like there is a maintenance void that needs to be
> filled, hence this patch set.

I can see that it takes a lot of time to do a major update of a gdb
debugging script after some refactoring like this. OTOH mandating some gdb
scripts update is adding non-trivial amount of work to changes that are
already hard enough to do as is. And the obvious question is what is the
value? I've personally never used these gdb scripts and never felt a strong
need for something like that. People have various debugging aids (like BPF
scripts, gdb scripts, there's crash tool and drgn, and many more) lying
around.  I'm personally of an opinion that it is not a responsibility of
the person doing refactoring to make life easier for them or even fixing
them and I don't think that the fact that some debug aid is under
scripts/gdb/ directory is making it more special. So at least as far as I'm
concerned (VFS, fsnotify and other filesystem related stuff) I don't plan
on requiring updates to gdb scripts from people doing changes or otherwise
actively maintain them.

								Honza
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/iup2plrwgkxlnywm3imd2ctkbqzkckn4t3ho56kq4y4ykgzvbk%40cefy6hl7yu6c.
