Return-Path: <kasan-dev+bncBC42V7FQ3YARBBODWDBQMGQEINJFLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-f56.google.com (mail-ed1-f56.google.com [209.85.208.56])
	by mail.lfdr.de (Postfix) with ESMTPS id A427EAFBBC6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 21:35:34 +0200 (CEST)
Received: by mail-ed1-f56.google.com with SMTP id 4fb4d7f45d1cf-60c4d1b0aa4sf2970365a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 12:35:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751916934; cv=pass;
        d=google.com; s=arc-20240605;
        b=LsKs5/phNqfQRpNkZYC+PISQkpLLewshh06deLyRafdwudt1DQv6owbXnVjr1iuIOi
         cuwy5nLNEJevEebLex5go1V/dviHaJ8EzM5XW+khZtbuu81bnudQKXKx8krwJExfzfCF
         TTySgtMFyK1anja0ysvXRA+fClsI4/E3BDObyDBBxC9D+tv7yNQYyClMvosq5Fi8OWAn
         OfRg/1AdzwWrfGRrDc+NyLLRDC1V7vq1n5jio6QfLMrkw5lEEXzFOlhkQTHZsnEQxBwb
         2EnP7FYNt0im7bQ7yX/twHKmhiPB2LftmSQw6exdHDeqWCkIqoMfOtRPP869WkVkCdFX
         d4Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=IdvBxOWFlszQnNNCqJBeBSc5T/l7KCDTdHYucfYKEHI=;
        fh=q4LwEp1mr+IwvzmvJ4KalQEpLA5i9rEqBGdtu+LGd5g=;
        b=LvnhOt4yN08tTWpl4IrCDXxfLlIwFivyqCNtry5lc7c5A0baW5JbYR2jyP4Y26v8p1
         SAnqdfSNlbVaXsB+Rw7MNVdhupCbdhANrwdzFdUQtlca9AsEznW2KTEH0lHbMRYFAhAs
         DL7Zua3aGM6o8D71QmyHO5FtY+ZN7dzqBMWejdy4yH2IS2ptzUbSYJ9LTpCLRHGWr74E
         xBtc3i5+6nFey9lTRLAgNlN2MZ9c0DB5YAkkFZ4XqoQ97LTbIS0zQ5/6xvy2fb6vDpJU
         oDYMpowtt7MCoWUDnLsli4WHyT7NsuubDYOaMWsveFxLl9tnKnomfxjfjYsmIInj05wt
         iRrw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=s9bgsMm2;
       spf=none (google.com: viro@ftp.linux.org.uk does not designate permitted sender hosts) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751916934; x=1752521734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IdvBxOWFlszQnNNCqJBeBSc5T/l7KCDTdHYucfYKEHI=;
        b=HKURPhE5YTS1NSzMehAGVk6v1txhAdTD3RzCG5Sli6oQbZVE1tS08RUq/NAOWfBYdA
         jAUXVEkiaf2FCkqjPz6HQWiYbRZAdcvkDq65PYsRqKDUhuZSVm91uk6LRZLNsATSMOqk
         mQHDQlpI7uJb0JvzvtRBTPwjHjzvsDIaGdsLtZZ9NX0goznNTIdchNL1rW7JoVaySvfx
         ebYdSTavsu1BflmYpbnov3R2z/UTsEj49cXxiCrRmz3y99JTxvrtB8D89w1QzYgkDLdH
         FsTSsQqk3WsquDiU81P7xYPyC6TDLO2C2XErBhZJv4/ecKFmr73Cd1aD/U4TivHTLemT
         UrUw==
X-Forwarded-Encrypted: i=2; AJvYcCXMGkOOegyU2jsTRs5rwYSq6+IG/FzYz1kwtksxYs+9ER75icA+Ij8HkzyGdOn6vEF0VQr3Ug==@lfdr.de
X-Gm-Message-State: AOJu0YygcB0hSZ0rOClQJMR1542EtUfial/j5Pb9KsqJlWfF8FkoFT3f
	WZS4dl5EYwR1xEtryohoK/luRqKoE2wsiA72i6M32j/9nRvhb7S7Va6o
X-Google-Smtp-Source: AGHT+IEU0jRv19hFVEVvQuVju6SB/uFE+HkqxhGYgTFS3pioxkvJTRV+KD+fFuDhxlOam1HGrGrvbQ==
X-Received: by 2002:a05:6402:26d0:b0:606:c48c:fb8e with SMTP id 4fb4d7f45d1cf-6104addbb87mr78952a12.11.1751916933802;
        Mon, 07 Jul 2025 12:35:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaYuHTs/K2GyL8EGHMY3nKhphvpUNWpkMO2StpalVuHA==
Received: by 2002:a05:6402:1d48:b0:601:6090:416b with SMTP id
 4fb4d7f45d1cf-60fdb4fd8d5ls2606577a12.0.-pod-prod-03-eu; Mon, 07 Jul 2025
 12:35:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwJflddzIdLIJnJ+7P2NurXKQC5rw/wXwTxpS/foKRWHZWnQ7ZbnSQAzJ9S1Lo+5xAUi7Z4ZpXnO8=@googlegroups.com
X-Received: by 2002:a05:6402:1c0d:b0:602:bfc6:f99d with SMTP id 4fb4d7f45d1cf-6104ae417f3mr39667a12.24.1751916930765;
        Mon, 07 Jul 2025 12:35:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751916930; cv=none;
        d=google.com; s=arc-20240605;
        b=W1GNtXacBLqkSQHUTRQFnq0Faa4SLYZANXaD82flFGYYSUGl9UEysfsWCFU5N1E5mK
         sLT7VtsbcvUlPbOU19KEPYUhU5ltAqeZkCfe1c28ymIt2UNhf9iuNOzJ87t55zQWbD4F
         5d6qLtvIG15HlE9Zt4bN7JuCmhLgcqYM/Kq6ba1Mt/PT9r+hgqHxa5g1Y3e8lUpeDjf8
         Sxy1Ukek02DBk+UlYs9TYGKnGy+atejDtwdQEGFxB8d8ZsFdeA4VlHcoMqjrOVJ/8L32
         NzJihBNR0GN6cw4Pyu8sr5jd+Pt5RoEVKb4Km1e53ffNre8rjI3C9nqDV1oa/LzN9b8Q
         2imQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Otyv2zO0XZSVF++N+FU4mfn8HTxzVXBK2tNM9StJTvY=;
        fh=UTBrOslN/qXMBQXKG5T9TLVa3v9Wh/23etSWjAekUIg=;
        b=D7SoyurhC3zILXbpwUpSlRFTMfiktvRdI1+MYPc3S9YpjRoe7jsneHe0WXbhTMK78V
         BqEYExgSIA6rlAaDuQw48s9zZk2UDpOYwqFQuHDJxSmjn47y2xmShdXqCa4zYJLKYF0R
         dZ80zdAkQsC6Z9E05+4wVFtf7RmXo/4Zf3ufRyNLrb9XC7/uQwOZxKnJR6bTrwVW/u0s
         OM54O0cUIjgUZUT31Yyxp7v1JJx+CvV9yzngmIlz3A093QozB5kwuc7+aw5q8ciQ6pEf
         iGJHo20GSEJDyOSpZ/s2/Nd48LX2AHJtpPoVVVpd84ojsu6299M6eWIK6iMGBVm6JvLi
         ZyZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.org.uk header.s=zeniv-20220401 header.b=s9bgsMm2;
       spf=none (google.com: viro@ftp.linux.org.uk does not designate permitted sender hosts) smtp.mailfrom=viro@ftp.linux.org.uk;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
Received: from zeniv.linux.org.uk (zeniv.linux.org.uk. [2a03:a000:7:0:5054:ff:fe1c:15ff])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60fcb0cd7aesi278117a12.5.2025.07.07.12.35.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 12:35:30 -0700 (PDT)
Received-SPF: none (google.com: viro@ftp.linux.org.uk does not designate permitted sender hosts) client-ip=2a03:a000:7:0:5054:ff:fe1c:15ff;
Received: from viro by zeniv.linux.org.uk with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uYrcX-00000003G1r-2czU;
	Mon, 07 Jul 2025 19:35:21 +0000
Date: Mon, 7 Jul 2025 20:35:21 +0100
From: Al Viro <viro@zeniv.linux.org.uk>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Sven Schnelle <svens@linux.ibm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Tvrtko Ursulin <tvrtko.ursulin@igalia.com>,
	"Huang, Ying" <ying.huang@intel.com>,
	Lee Schermerhorn <lee.schermerhorn@hp.com>,
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <20250707193521.GI1880847@ZenIV>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
Sender: Al Viro <viro@ftp.linux.org.uk>
X-Original-Sender: viro@zeniv.linux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.org.uk header.s=zeniv-20220401 header.b=s9bgsMm2;
       spf=none (google.com: viro@ftp.linux.org.uk does not designate
 permitted sender hosts) smtp.mailfrom=viro@ftp.linux.org.uk;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=zeniv.linux.org.uk
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

On Mon, Jul 07, 2025 at 12:17:11PM -0700, Linus Torvalds wrote:

> and we do have something like that in 'struct seq_buf'.  I'm not
> convinced that's the optimal interface, but I think it's *better*.
> Because it does both encapsulate a proper "this is my buffer" type,
> and has a proper "this is a buffer operation" function name.
> 
> So I'd *much* rather people would try to convert their uses to things
> like that, than add random letter combinations.

Lifting struct membuf out of include/linux/regset.h, perhaps, and
adding printf to the family?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250707193521.GI1880847%40ZenIV.
