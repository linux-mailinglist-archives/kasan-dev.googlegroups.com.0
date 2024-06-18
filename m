Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WSY2ZQMGQEGJ33LHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 25D9E90D771
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 17:36:20 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-37611e4bbc4sf3696015ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 08:36:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718724978; cv=pass;
        d=google.com; s=arc-20160816;
        b=BAYcmH6Un5NFccwBmkjBwo7eYw8MW9kSSCd4pQpJAOJXRDOxFdzGtBCU42BJlKjZyC
         6uYkODbP5b75b8h95KE3m1NkMoHayaQd5NCww5xCRcBeIquPJoAJtud+X61eZoQDcw49
         mghCUOrYvYJCDTsxK0s7jAkqBPDUFcyrz8NJV4KIHdwQtNEmqY4kSCULlu7R9wallD0v
         TM6NPfQtTRi1oPkSfAxoI+JfIj3+DxoZUBfpmibstmgEb5bx+z60IlLBAPxSc/bgI7Z9
         3ePOz4LM/Wc3FsgIBMl7KO9gR68XjNeSYTBuZ8g5eFt5WkwzvJlsY/h78PnEtE8grtVE
         bk3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sj7LHd2WDldfkJ4ZPbgCjTjf00ooK5RLQLYL0wGKljU=;
        fh=tfApxI6nlwharHbulBNMmJQcXLE0ff+pEiv7X7OaUmg=;
        b=F34V0a89IzJ54QnpIxtigv1DawYNoqOqZ+1/hBXVM1296k/aV/Gr4YmaihvK9EYSEH
         a+WY447xG4a1z5iqT+RcbPj8i0fHJiP4kkmu5ZeAiyu3RowSUV97ZrjKy7KXrnqvYa+N
         MavlgA7Lp8vCRARaqDVeRXzQ/APmXwMkTIXijou4HaG26omVXScWQz8nFvSYTqxnfyMi
         1DA/wYz9VhTDZhbGi0K3pjt939CDd6kYu7iCRGBAbbNrk3yh41oQtpJcVgXZH6Pk+2xC
         cvtur8KIxtaPP3Lz5llViZQ1Rf7s4Yae4YI44y5cM9naGlhQNf7HkZG1ORPGWsP3Jj2p
         m1Xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VwMpumDV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718724978; x=1719329778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Sj7LHd2WDldfkJ4ZPbgCjTjf00ooK5RLQLYL0wGKljU=;
        b=mQMYeLJixMmASwyUTpGT7Kel+clq6Ew1XxAOB9++AsKb6YqhOLgoJgGPZSDvBe4qni
         BKhr9M4w8wbwYB3Ee+KkAcOIHlz7gClwmdxaFNQfRIEJ44E+p/8ZetQMnB0q4kJfv3iC
         XuO2ntWBsIcHIgaoq70E77O+fK2tDFDN67BKi9L4WvfiZDRky+rLu3qADqGwuzVENd04
         aK3Vu4D7Qdcyt0iw0VS2uuUNSx/MWNI4Z6YV+0+EWAEMrnqpCSAtPWp+Uyp/OdxG/5Hy
         XEu1H8rRpSupUYKiYGTDom7Dkn6zhLXK5uTtc/9o59gdWzdMkWsJ9uAFiFm2XUv8zHlp
         NRbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718724978; x=1719329778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sj7LHd2WDldfkJ4ZPbgCjTjf00ooK5RLQLYL0wGKljU=;
        b=TsPreORWBoY/0KilpV+9Cf5nH2LLppWI8PMucY4FAPL1WYNXmU3/SRIvAhNeDLzy1L
         +FXJMenrpZRhMGw9voCvOiCma3YqVG81q3bYWUEzpQ1SU0e3Co/Se7tb386F/JQsJUF2
         VBh5xX7HgC7MkMCS+k9nBjHFXnaa3NwFiE3uh0nBWQYSHFOyvD8hJADN10umLcCdkjJR
         lrsiujoV9iX7P1aYkM0f5WWeFzw0TlQ8YORLylMPfhANcgsM5ZFtPTLLQV3d1J7EHTAB
         T5GoufiR8J4iAYZ+2au1ySXpXk9FjLadRBNdgh133f3WyleUJwYn5GlLlxYziyO+HPUr
         CAxQ==
X-Forwarded-Encrypted: i=2; AJvYcCVMO+W0yXSkF8cbWFOPW3MHT3MOrFQHk2isjVPiu/QNROgOIHu7qDkU5fGfdMM+5buWrYe0l5xYqPlPmU9FGMGaADWBAkW9pQ==
X-Gm-Message-State: AOJu0YzerUNrqQ9luD9Y1tr4ltSRgVyLfUq5Rt+5ImeFc1yJzEP0VKu9
	gZTn+Igq4o4HuOPS/DSYuXo6+dMKxieT7dWgcJwK6VsD1hEUyWWP
X-Google-Smtp-Source: AGHT+IG4OB4lUVbG2nNweUtUMX+gHXVdNreofDwxix5QROMT08o14dscRbdwRJuVtSbgjXBv9D8beA==
X-Received: by 2002:a05:6e02:1787:b0:375:b567:a6af with SMTP id e9e14a558f8ab-3761d681458mr507775ab.12.1718724978503;
        Tue, 18 Jun 2024 08:36:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3d07:b0:375:a4ed:3509 with SMTP id
 e9e14a558f8ab-375d56a5258ls43442425ab.2.-pod-prod-03-us; Tue, 18 Jun 2024
 08:36:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUF06iqwMncWvikHXpbyVxFMc72Fgt934JFwIprb/cTU7Ks0a7ImuKJ7yjAfN/gxKFUqth/bjHS4MWC3avmIzIPL30VDSpbDUgfUw==
X-Received: by 2002:a05:6602:150e:b0:7eb:a2fb:6979 with SMTP id ca18e2360f4ac-7f13ee3ed23mr27828739f.8.1718724977642;
        Tue, 18 Jun 2024 08:36:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718724977; cv=none;
        d=google.com; s=arc-20160816;
        b=U7xF4ZRQhViB7UGw00LyU/CE1Af6meK5fvg93qa5NP3PGl0WYyPCq5dlLxMN3SBvTb
         iWIm2asIulqgD3FevDmuRJYTFlFyo6DLfSDuqZ1rxgz/qYNX1K+z/X7Tmohj/ZQTwZ1X
         EepQVBhtih8uzms+TYw6WfcGdogi1sSYnvC2eSAQg9CQu1B1ZKQYeYCpcKqLGtNhEvEG
         c1UYuye7t4hs8pp/S60zYF8f3LS7nivIrRn5lgRC3B+YzMipXpyLBZxHJQ8V95QoSvq2
         h4a9TJJ0l5B9pVm5tjkb7nlkEnhYq+zHHMSzWZ6mLAMI0xjoMmw0RFgE0bmQ9b6Fy/K8
         s36w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5RGeJPOFaWHdjpCL2phNpFb4SArUUUeonhkd+IsWbC4=;
        fh=jXnRlJPedHvedg1cOlmnafr/94Or7l6l2S2IjSltr8s=;
        b=OdYv9tyGBkeCWN6ASI9Sjz7/VYhrk8z/kAj0cxR4d/tEd6ahSlJ+QQi/ySXo8aeHau
         rJbgT2lLP+W/E+IFHskpE9ZSwzUa37YP8tOg2l8hBGkpGyfc1aJt2wzCbno/bHQ9HAr2
         5PAfq5oJd3iuot6RZSDG/BNmW8RzZJ0JxIUzq+mVZnB0UYIt1ac8q6SqYwd1nLzmr/ks
         fKtHO5m2AIlB3ebECZCWCYU6CZBpvt6OPgmjZejrMWksx/Zh+ZKsCNZ1ThKAGipb54rn
         +Ri7XrTPLMJhnpxnnSz14okA4x5jqrcz6uEihNB0oQEehyQPNrA3M2IEhZR/YsK7mOwW
         noiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VwMpumDV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdb75e03asi50649039f.0.2024.06.18.08.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 08:36:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 46e09a7af769-6fc36865561so1513600a34.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 08:36:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXowx7RqNGEkKNYjLc/x0athJNdVQeETLUwjBTD20/aO3uOtHS4NqvpUi2omrVAQaj98OzYCUCyXtAgvAhloATKY0tYUw/DjfkXww==
X-Received: by 2002:a9d:6510:0:b0:6fd:6240:9dba with SMTP id
 46e09a7af769-70074ebf134mr77156a34.16.1718724976930; Tue, 18 Jun 2024
 08:36:16 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-10-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-10-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 17:35:36 +0200
Message-ID: <CAG_fn=VT5u6fn6eaqzdB4bDZ+aw0kKBta7_Ff2Thn813RG6EVQ@mail.gmail.com>
Subject: Re: [PATCH v4 09/35] kmsan: Expose kmsan_get_metadata()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VwMpumDV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::32c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Each s390 CPU has lowcore pages associated with it. Each CPU sees its
> own lowcore at virtual address 0 through a hardware mechanism called
> prefixing. Additionally, all lowcores are mapped to non-0 virtual
> addresses stored in the lowcore_ptr[] array.
>
> When lowcore is accessed through virtual address 0, one needs to
> resolve metadata for lowcore_ptr[raw_smp_processor_id()].
>
> Expose kmsan_get_metadata() to make it possible to do this from the
> arch code.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVT5u6fn6eaqzdB4bDZ%2Baw0kKBta7_Ff2Thn813RG6EVQ%40mail.gm=
ail.com.
