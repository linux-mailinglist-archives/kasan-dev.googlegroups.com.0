Return-Path: <kasan-dev+bncBDH7RNXZVMORBHOKVSGAMGQE4ACFCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id AC81F44BA12
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 02:49:18 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id o1-20020a635d41000000b002bd97c0a03dsf662103pgm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Nov 2021 17:49:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636508957; cv=pass;
        d=google.com; s=arc-20160816;
        b=r3nw+YlkvYhKEojWEEo6RWoi17J7kG7awwtTkfs8vSLpobFCUzP+X/6QUzE9BLM7G3
         pWoaHzAu16gdjfGI+hdDQlw7uJibVfkBwPDKXROowIFj2znRhL+ZYo/eYuVbNd0rLKwm
         d+rDWoFvTnYkv8sCqazFOL1jfHyTitM7liZYyEoYWqKu5exduj5tkN1U0kZz1G4zN6sU
         9tOd6ba/kq12u0ib6mGSvVhMkk6zmLbIeFdI/ilhqDZka6xuHNknrktvLSlqGAT+m6UU
         WGTp0zSfW0Q4CrcKPfVvjJ1OMhmLs3O7tBSCo6B86oMLCzVCguwveMPf7r5TeZpx/DMD
         Kc2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=+ckl6RQh5aBghXiAi0WIMmdyv1J4ATtSvLITqhRNp2s=;
        b=Adj2fnlOMLB8Sl9VqipsA1BvrW4rkBLG1ZLeMiNc87af3Os9e1jgTz3PsH2G7fNKO0
         xmDOTJf0naPNvhK69QZ0BIYyu1mCF9WshCpnCzxfvTPgv1mnX1KkJA2s2QxW57I7WXDW
         Z2CMeYtxgAElZXo7yOBxbWq/Jc5r49UlJJiwvbhLWktEp6Qe4S8Q3InBiYFq1JG3DcBx
         l5vghr30l4Sld8IC7eW3wmk1aBR5kucvuRTVpyv7jpa4GwU7iubmS+gwSjgULvX5uqax
         W2EXJSBX/7SMMtYfNxTbbWCEI1hl/xUHJvu/I4/+haDhevVl2fzeQlC5WCcOVQyaP/mu
         WjXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JcAnLtwI;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:in-reply-to:message-id:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+ckl6RQh5aBghXiAi0WIMmdyv1J4ATtSvLITqhRNp2s=;
        b=KehhhbDW2ddNUeai/XDpf2vBB63/DH7nIZmuRx/BFgKgai8ZtEWIoKNPL7CSKiOyMx
         fIOWovB1wDjUUeiLrbW5qG+jt5F3VfF3pA/gbWgX6ruuB5cMNKXQ9bP6djuMvAw5kJAD
         GYrhisxRR64EvVxJ9mXYfSGabP3Gxx3idQHgum2OF01X/T7G8fXsCt5HZ3FX+rC8SzzK
         CHuXI8OPRXrs4pl1R/8dRDq7wjUXN2wad7puIO0Lse59LaKlTQnDJSWBrWK1FhLixwc2
         5MIGvR6PFbeAXsjWa0CGo2hZRlWKGpyZGTBuTNRN4hcjiZshv+lKzvNPCNO3oGXHq//l
         5vvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:in-reply-to:message-id
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ckl6RQh5aBghXiAi0WIMmdyv1J4ATtSvLITqhRNp2s=;
        b=47LyA3tq6SiP8/B2B6vyW9BskiqFb+keAcYVQyNq9z4Y7G9DncWNVg0VyLnYQTQl4w
         S5GgUG844R5gkE328QNFOQmrgpjEOghZ0IhuFbGNgFC6TM0ZXlhzGqa6Q+8FX/ldcvpG
         GvMQWu0S9JwCoL0CbO0Q6aY6Qq3+bOmZpY3D7jTl7zg3LLD2O5RB9BMvH672rf4CZaZu
         E3yC9X7UK9rb8Pwlu152B6Vm52G4flM/o+WxArE0hw0u5wkmAXGvUnJrKxJkTr6xYvoA
         aPIEMAZzaHeXaDvDVwpRR2ZLz3cGbIV0p5FO8UhYQGSgu+bY/KOLUYJF6im/WGUNY0v0
         hEuQ==
X-Gm-Message-State: AOAM531I6QLNIlG4FIWkXfphfYBMlUn86jXLYbLaFHYAg7XEm8+89xpA
	s/89hxF6utWJfOvJ4XUNpeM=
X-Google-Smtp-Source: ABdhPJyK39oPeNaQ527AqjEOx0cu8AmEzc8AJtbH5HI8OrGEYNa2+k9wPh+qWbAuCv7bSGa+Ax74jw==
X-Received: by 2002:a63:f644:: with SMTP id u4mr9525005pgj.300.1636508957135;
        Tue, 09 Nov 2021 17:49:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:11cc:: with SMTP id q12ls12085946plh.2.gmail; Tue,
 09 Nov 2021 17:49:16 -0800 (PST)
X-Received: by 2002:a17:902:f551:b0:143:759c:6a30 with SMTP id h17-20020a170902f55100b00143759c6a30mr7105838plf.0.1636508956536;
        Tue, 09 Nov 2021 17:49:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636508956; cv=none;
        d=google.com; s=arc-20160816;
        b=xeJcz4mjsozxtxsgZTvChlGClSgo0Tj7VI1LAgoAQeoKr5+TK4g7D31xA0P7ojt85T
         9++Szdhl7e8vAqV17zeVNe0J6xeZgUrnOvyLoWoRY5oeBzJaeZ8weH6mnRM1SIT5DC+h
         HBfFjV8G8PKUl9pvsznWk1tjq0BKppN/r4C/3IicNLBGbxoL16TexNJsneMjqYEjgGBe
         xxIGI0Ri5RQzmZS00rnBdDQj8zVzEMOb6iardTEEgOzpPOH4qIzQ9LlvLdRiZ4+NbiQW
         aaYy11K8Q9sbvuwrSJS7MP4NfXG0QVzkfogU9RfWKMR60uJiDJyB93K4Aaf/6W1tbW/w
         NUWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=Q1Ic7kOOPETyhFj1cyuEbcKYl8I2Bp4M76inzkMgFYw=;
        b=Oz4+zDKkldNMnVdIF7X3Dw6LQr8viZtfE2kJE4gJGlTN1FO7mX5HCDoq/od76XH4+T
         zPWHKbB+9jIr/aSCxCgKz+OpQXgPWzdmQOQ7gmo9At9MiDDsx18fA5+pyaQPs1K4ZBgU
         K7CccHovijedf5GGbgD7Q4tVeyASkbVuuuSfHov9W816WiaTuYdVAM/vZx1Ztav8MSgg
         VelD3xZwvYuAry8byxivSiFKOgw50ZnaW1FMdJaPZi3ofX3M9FqA6exQ7MPl3DZU5++f
         E77etf3vzg5la+2gy9lXiNBRvQ8Fkg5I/+zdUWaOqkoslZUS+NbHkLWbSQWqgnuScqXc
         EhMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JcAnLtwI;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id g12si60217pjp.0.2021.11.09.17.49.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Nov 2021 17:49:16 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id gb13-20020a17090b060d00b001a674e2c4a8so246394pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 09 Nov 2021 17:49:16 -0800 (PST)
X-Received: by 2002:a17:902:784c:b0:138:f4e5:9df8 with SMTP id e12-20020a170902784c00b00138f4e59df8mr12132125pln.14.1636508956033;
        Tue, 09 Nov 2021 17:49:16 -0800 (PST)
Received: from [2620:15c:17:3:9e39:3ebd:7991:6639] ([2620:15c:17:3:9e39:3ebd:7991:6639])
        by smtp.gmail.com with ESMTPSA id u9sm12051146pfi.23.2021.11.09.17.49.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Nov 2021 17:49:15 -0800 (PST)
Date: Tue, 9 Nov 2021 17:49:14 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
cc: Andrew Morton <akpm@linux-foundation.org>, 
    Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
    linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
    Ingo Molnar <mingo@redhat.com>
Subject: Re: [PATCH] mm/slab_common: use WARN() if cache still has objects
 on destroy
In-Reply-To: <20211102170733.648216-1-elver@google.com>
Message-ID: <146e59b4-76c-69e4-969-ce8a75ccfe5d@google.com>
References: <20211102170733.648216-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JcAnLtwI;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Tue, 2 Nov 2021, Marco Elver wrote:

> Calling kmem_cache_destroy() while the cache still has objects allocated
> is a kernel bug, and will usually result in the entire cache being
> leaked. While the message in kmem_cache_destroy() resembles a warning,
> it is currently not implemented using a real WARN().
> 
> This is problematic for infrastructure testing the kernel, all of which
> rely on the specific format of WARN()s to pick up on bugs.
> 
> Some 13 years ago this used to be a simple WARN_ON() in slub, but
> d629d8195793 ("slub: improve kmem_cache_destroy() error message")
> changed it into an open-coded warning to avoid confusion with a bug in
> slub itself.
> 
> Instead, turn the open-coded warning into a real WARN() with the message
> preserved, so that test systems can actually identify these issues, and
> we get all the other benefits of using a normal WARN(). The warning
> message is extended with "when called from <caller-ip>" to make it even
> clearer where the fault lies.
> 
> For most configurations this is only a cosmetic change, however, note
> that WARN() here will now also respect panic_on_warn.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: David Rientjes <rientjes@google.com>

Thanks Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/146e59b4-76c-69e4-969-ce8a75ccfe5d%40google.com.
