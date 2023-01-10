Return-Path: <kasan-dev+bncBDUNBGN3R4KRBGWQ6SOQMGQEIUWXI7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EB965663BF5
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:55:54 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id k20-20020a05600c1c9400b003d9717c8b11sf6018827wms.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:55:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340954; cv=pass;
        d=google.com; s=arc-20160816;
        b=hfJPgDDImEpTgnGsPwwQ/xILl/izChodqcREf5lhn3j9gO2SIeSCdE03cgC3aMbk/J
         a+4A/pQmIDGpFBCi5jhI0KvULfvvGHJZNxFwJBgno2msVMi47vbtWgN0S05FKQjk9kVK
         B/oVeCftEo5miZ8qSARew/EhUATvYGpSKmjyg8iKovSMLwQRgZq6BzHRMhijhIuXUfE9
         O3KfMJaxsn+XL30XBUctNNATslO1zB1pssH4RYQV8/zyf5CNQDmVkWOW2BJCAwhY60fe
         pcdPBsKbqnXbUqkY2jsKJymbvr9aVAOctKMUk1LnoEEwemtABVxLPSY80HadzCNSylTo
         oV+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=R7ypE/umihopaSlHuXN0U+EaQpEQi8tPszh4edgman8=;
        b=mEv3imnowPGGoQ2q0anyM/tq+dc+r1iMYdDLiZTZo5JOefQ+d7AfYPmmWZuykplWSh
         Ap9wIHyjW9DcqFLP8uyyBlA0N8cKoGXLWq8u/57TYuCFzMpCHtZrppKX8L20Oqmt+H67
         OSjGq5PSMe4IfryXwt2FEGbgXmodFvwHE8UZIvWzmx8jrDwH1qH2kNdflUxTRzTmkug7
         TXHmn4esbyh2m4IzoxPhWgmtl83JvG+94PaqcHbY42ZKsdHglwgN8goNW9WhApi49Z61
         NxXSz7GMhDk8P6hoNH4LNs9SYlV77GPz6p4vIZ0kJfQ6EvkqeKdirD2b6yoz9upZW7Yf
         Au3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=R7ypE/umihopaSlHuXN0U+EaQpEQi8tPszh4edgman8=;
        b=ZOUu6Yv/9BXmnotrUEDwPeMj3pomSLzoKQjz8oen0+utVvVbcaq7G9+HFlvzjrvxLx
         IhRrL0RH2PYX55xqxuYnrY6mqPQDNqvhDqR/FTG/bUgAlX05AHyb2424A1x+vFaPg/x1
         aRDwdTuHCzNEz1il1oISpMSkveawrEV1sAjWV65Jqh9C24sdRORxrnkvXXp2f38i5ZjB
         GVoPwzzLOqwaygVAFWycgrimc3kfymZfBcnQyNuxcCuBGBXSZXrxAB6AF88Tw2/QFSlw
         ZE4cE194h/q5EeZXjAZY0TBH8SnoY5jkCJpl2pPWQLsfmbrxrMp2LxTvub6mIAPJYwpH
         57kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R7ypE/umihopaSlHuXN0U+EaQpEQi8tPszh4edgman8=;
        b=JTEHyGJFLtUviLtqudShOOJBihmmo8K55vPLa3MRaO+COGY4f0q67K9vqa/GZc/m5t
         HBrLpOAPhGGBA7RvAlyfQ6Y4jfgrPuFJGsdK1Tp0N4mWAwIJ5S8Dqm2NbQmo5get4Xnh
         bbWN5CckYJXICrx+oy9y/qwN/pYiB3GdOfShz0Ph2/0P2dzKIbDy6cLddOyQf2fo3Tsf
         vd5/inA1GUQ5SWGBPWfexC4oZlDCcz/RPcaYLzu83R+ut51YKfRHIbvjMiV9LXHTZKyK
         ntkoQpsRkfyrLjpe+iyQzglwa9g1V7qij25ABlHynirtPNlqDWD8KnEjErUSTMbTH2RM
         Bibg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpquw1Ig3eNXtZUB+laOGOUljHbB+C4A8k2yGIafX+Al/FHucIl
	s8DcGl5XalHiXLiR9Sey94k=
X-Google-Smtp-Source: AMrXdXvfem+pYUXnfwqWeYFP8+1q/kagIpxy+x47Wu6gWnb1/Th2cT+o0SL4JboDYbVVCY6cvrr72Q==
X-Received: by 2002:a5d:4d49:0:b0:2bc:371a:8a9 with SMTP id a9-20020a5d4d49000000b002bc371a08a9mr322678wru.16.1673340954422;
        Tue, 10 Jan 2023 00:55:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:541e:0:b0:3d9:de91:ba54 with SMTP id i30-20020a1c541e000000b003d9de91ba54ls166170wmb.0.-pod-preprod-gmail;
 Tue, 10 Jan 2023 00:55:53 -0800 (PST)
X-Received: by 2002:a05:600c:3d12:b0:3d0:bd9:edd4 with SMTP id bh18-20020a05600c3d1200b003d00bd9edd4mr48343901wmb.0.1673340953195;
        Tue, 10 Jan 2023 00:55:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340953; cv=none;
        d=google.com; s=arc-20160816;
        b=inEvmD2kmMZEkQUf5ZdVf44GnvtbMYGjpKF1JGaC+d+IbCF1yq0YRihm0RMiT0ofry
         v0RbW2TGJOOXhHM3Xx0D8LOPpEbHTioNaBBuqW6bBdsJ8VkK3IEo0Aynlcb7LoFnJPR/
         aRzkz5p6DGeO53gvVq0JSeNW7ldLjyi5d16ZHyOsAIG2fSTXNig21m1yJ1TSGXnYHvON
         JLgqbZftmsTfGsC3lQ1ucCTL9vUa6vwpCAtRxN/lKmAbXznjRC2PdDDE114fJxpvyt06
         pwTQFRL+I2RAX71q+DJG8TnU+jJFInVNCE9hY1/tfGelhY+Vhpyy4zacSeikfUPww8m/
         xMCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/WcULYb/0eg2sVvj/bGF707HDaGdgkGvXhwsCCABbc4=;
        b=lrqWFXJjsA38Av+sBI2tbdXhhf8xqn04Aa0bwWzrG2iqMmVkV5GMZAjHqaef3VORnS
         2PS5V3TUTfJkzwkayihclaR6GUy86kLAPzx/Z0JkEA8ZtmONDr00V7nN0L0+fOan3iI5
         1qcj8GMP4cWp96snC0wx6qmY8nte7qClxrioDX8tQ2LtawD0nYiM0wE3MCEkEbCoLWbl
         hJq1483V1Xufa4+QPjdAAt6VxHrVayDdmQXBJ60wWR8UEVWXc0Rr6u0sjfqojfQ4Zscu
         CLYuzUD5AGzn5wfxdnKsFzSVyR0+1dfi6bcnEBQ2Ek18Ej5uFsmRAGktDDVorRcOE1+j
         dKmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id ba30-20020a0560001c1e00b00241d0141fbcsi496137wrb.8.2023.01.10.00.55.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:55:53 -0800 (PST)
Received-SPF: none (google.com: lst.de does not designate permitted sender hosts) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id E18B768AFE; Tue, 10 Jan 2023 09:55:49 +0100 (CET)
Date: Tue, 10 Jan 2023 09:55:49 +0100
From: Christoph Hellwig <hch@lst.de>
To: Eric Dumazet <edumazet@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dan Williams <dan.j.williams@intel.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Marco Elver <elver@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux-Arch <linux-arch@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase
 MAX_STRUCT_PAGE_SIZE
Message-ID: <20230110085549.GA12778@lst.de>
References: <20220701142310.2188015-11-glider@google.com> <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com> <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com> <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch> <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com> <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch> <Y7z99mf1M5edxV4A@kroah.com> <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch> <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com> <CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
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

Folks, can you please trim your quotes to what is relevant?  I've not
actually beeng finding any relevant information in the last three mails
before giving up the scrolling after multiple pages.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230110085549.GA12778%40lst.de.
