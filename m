Return-Path: <kasan-dev+bncBDUNBGN3R4KRBO6IWXDAMGQEHDKEIQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A7A1B89CE7
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:10:05 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-579e84da8a6sf542743e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758291004; cv=pass;
        d=google.com; s=arc-20240605;
        b=U2RpdjU9cCF3twDwpbdQblK7UtZMcLj/lJ8sSSPWC8kADe/JeR08gZKwK3jLGstiio
         n0kmngoV1BQSHlxdX0Z6gNVy8tkzmw1qIgxBEoiWsMfaEP4mSCkx7V1uxw8xSrrB1d5F
         eiPwO3uPioby8JVVmGlT1Bxc2cfaBY0BySs8HiqeFKQ1aqp7X6UvSOlhp2jC61IpAr70
         M3uXLUaQhi8JuQU7tFsfinMb61/eu+zh8sXlqVX4hRFq7QXzdyQX0lHDP9g8Ob49h5TM
         nVMRGIFT2Wt5haaLqA84yO225LOAD/BtWpVdqh+669QIG5BKBAzIjzmlb1P2c2oH4A2v
         mB9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qnvuBMNKRUX4lm1ZsWWVspEzGBpu0mCnYVS5NEDiupc=;
        fh=pY9ZUFsTeUjy4MUNzy9DNDPlngxtmxvPrL3cklRlRZk=;
        b=HHoZApCfA28ywxbS8MFYLXx+ON7qWikxrxnPdUBb0+u6ftczY25ScWF7WOXIribVgW
         /W+/kGiWLSVm0G9rNUKy1ilBsOfJUjGRz7GkQf2YS/wu9uK6fg/QAfH8vSgNKlRC25LM
         Xuu/DrVl+s/w0w437YkUt5yl54D8EFxeYcvXXAgosh4hKoVtJLxljWOsKf5+bg+M5YIT
         pmG6iRYL2HsunxIgvqocyn3v3GqhJy7jBQSRK9efjedvpT2RJlBgj68YSb9Jz9WuyH81
         XULP2aaqct9Gv6+Oe1Vtckv0GWXvIWG0PHXAPWZXXV28pdamu7lQxsFaMYHNZsza1deb
         Pnxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758291004; x=1758895804; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qnvuBMNKRUX4lm1ZsWWVspEzGBpu0mCnYVS5NEDiupc=;
        b=OHIDWd/hbzS1GrMMVURxHW7Q3ZsGl5CANFnR9/ypLZdHUUOkONAPOl+oA0agoIEzrp
         LSXrWgQGco+NdPGMxwTgDA9KNGi0uyUliyVjN/H20be9XfLMnNwalUoO2kDBHV8SXATT
         P9mk/HazszlK8Akcwbiwstx9nffH9oiJajG5tD8DGRHDUiQs7KXFhR7VYwmavutDtBdK
         4GEKkNqQbxFidby3bDnHxg2Lpqlv02UWb3LZUgAhT9nMyOuD7d496yUbAyugzoR7VUf7
         CM5lE0FMe5PRS6i8lKP6TOYhIU+Ec9+X2rrIvI791taDg5yli8N1W61HhRTnjJJBLISb
         ejNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758291004; x=1758895804;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=qnvuBMNKRUX4lm1ZsWWVspEzGBpu0mCnYVS5NEDiupc=;
        b=Lv5jq8SjlM6AUtOLWz6rK7znTjorYLtZZo5TVnIaXM7zmtoYT/FQAd27mQxHKgKoWj
         CG9WPJli9Q6gbW2AqtA5/YKThzQOUON2DIBob/jivtDba1nDan6K+D6Vlqe1Ibuuqc0+
         4MQxpLekHPs5z7aHykeRaS6+ty8qJGPRl5WOyYz7f4FOQP/KKEYRIXr6ILKTiRhjgZrZ
         2pFEBJg8XAVZyrwLSb0UlqyFe6DjN5iRON/NVjAsSt6VkYLx25ylKCRNSP8oFUoe3hpB
         KAJLAKMTHNFwdMnLTQ1XXflzuVAjunBagA/S21b/xa7Qs8SNOFcW32ITekXp8DWT2LKW
         VZQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZx1BWSb0YQnZk7gCGxCnrrwEixdhBO3HHDwSFBkNw+9EpMl+S+FK/feiFSFijwBALm774rA==@lfdr.de
X-Gm-Message-State: AOJu0YxqeAF9jP5GUhnv70sEIajYGwZ9ZK9snkaPvWqbxxEGiw7nct/A
	6CMjYjyQqKg5j9/1mVP5VwiOI5hIwCGFYAlKpijEASJIbjZSmB19qygE
X-Google-Smtp-Source: AGHT+IFFkz3RTvlBEshu+F8U3iZlqZMg+vcleEmVuQvU1rtwiYRYi+NCtTLzd2yD8CrwuAWfqEFK1w==
X-Received: by 2002:ac2:5f1d:0:b0:563:2efc:dea7 with SMTP id 2adb3069b0e04-579e375c97dmr987147e87.34.1758291003981;
        Fri, 19 Sep 2025 07:10:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd67amyue4X9h4Qyn6IAhZV/xqxqll2Y+zaZqGOpbnpGWA==
Received: by 2002:a05:6512:414e:b0:55f:5096:7778 with SMTP id
 2adb3069b0e04-578caf908a5ls219050e87.1.-pod-prod-01-eu; Fri, 19 Sep 2025
 07:10:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRs8unj2p64904aroj3DFYInl8F5Vo+zlt4jh4foO2deqJFNR9yOJqwGdBU5/X7SV+tleBj+pAqLY=@googlegroups.com
X-Received: by 2002:a05:6512:2242:b0:571:3afa:33e8 with SMTP id 2adb3069b0e04-579e169452cmr1322150e87.1.1758291000495;
        Fri, 19 Sep 2025 07:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758291000; cv=none;
        d=google.com; s=arc-20240605;
        b=fM06TTRms75M0XWj8Zdq4dTn6sOMZuDfSxeQooxYCyrbCxiQ7bXorF2MVa/0ipGYmK
         bKQCMFUA9P1PlzIMhfDBvUy0LRt9Qft/MFkqj8vx0Ql7xEcOwAnQM3UAidxM4oKU7GH5
         7U4CG2z5Fo61F61C3GVMs2IJ4EI7WC9n9bSgWhe3LsGMd1kmWIx0e7WuO0kDbDcEmLRt
         i5PpfKfLkiublDapkkYtw+aezrIVwEswTUPHBy0L1fg+Donq8L44wdh4E6ThaLRWXiaM
         Vg2RH0/Cs6rZ91CMW8qFIVtXvHkB5Ne6PS74aMCUA1YPIFTk6ot+G6s6YjDkWCAUAtKq
         b4Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/+B9KGJ885tcqcRdpYW7pcueEG9ta0QWlanF7bRjaUs=;
        fh=P5eIro9UGdx23XTNWTN5Twl8qouPrH7ygQJNKcnxUKg=;
        b=U1gRSX19xK3awlcNqCuKm/gyiO4mEsWDqNT7q06fRLnha4prFEMx3i+oyXydQRX4bw
         V3sZ3wchR8GAuciPQge04OVZ4pugwaCBSX5QB0tXFfVyGgKBs+um1B+tI3XHChkK02gd
         6DwVUBCRd6rAHGMXffi1xLKd0XKVZRyrrQJmA2pmJQOFi/zhAoODmmIwA2zFz9fu1zoC
         12s8+P0gS8m1GMxo/EJ7lXG2UY0UL2BKO9AX+IG8saatT5bnGINW0FtYlJzRJNKufI7R
         M2M06Yheserm9FOnpxD9qcALk91WKvV8z795OG0yT7rqSFXcPExwlPexDitffPeT2UqX
         gyxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a7a8045asi91864e87.3.2025.09.19.07.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 990AB68AA6; Fri, 19 Sep 2025 16:09:54 +0200 (CEST)
Date: Fri, 19 Sep 2025 16:09:54 +0200
From: Christoph Hellwig <hch@lst.de>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and
 Locking-Analysis
Message-ID: <20250919140954.GA24160@lst.de>
References: <20250918140451.1289454-1-elver@google.com> <20250918141511.GA30263@lst.de> <20250918174555.GA3366400@ax162> <20250919140803.GA23745@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250919140803.GA23745@lst.de>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

On Fri, Sep 19, 2025 at 04:08:03PM +0200, Christoph Hellwig wrote:
> I started to play around with that.  For the nvme code adding the
> annotations was very simply, and I also started adding trivial
> __guarded_by which instantly found issues.
> 
> For XFS it was a lot more work and I still see tons of compiler
> warnings, which I'm not entirely sure how to address.  Right now I
> see three major classes:

And in case anyone cares, here are my patches for that:

https://git.infradead.org/?p=users/hch/misc.git;a=shortlog;h=refs/heads/cap-analysis

git://git.infradead.org/users/hch/misc.git cap-analysis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919140954.GA24160%40lst.de.
