Return-Path: <kasan-dev+bncBCW677UNRICRBWPAZXVAKGQER57JOWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 677088C70F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 04:22:19 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id m24sf24350853oih.16
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 19:22:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565749337; cv=pass;
        d=google.com; s=arc-20160816;
        b=FRqoJ51LyIc4oS0syJs0eWTSZdrH4+slzg3Gzf3q97rOVaUNhTGF9LP4EabAc9unmV
         TFf8mglfqUTKHJcqO/BtMiXea/G2sxjouDp4JDtW7POy5aGyD3DoZnmRHTPMAgiR71xk
         U0kVBKK+qu0DORHH4vGlUidJY+8J0699e5DOB7eT0y+pDe8OzGNn6+87nC7KUyYo6d9j
         prTBnxRjux7DxtR+wx9M0CDHbZ7BD6XtSoa/wk1PZ5AGPeV+cvjxP40G5/4bb1zNqD1f
         08paFWaxo+CUohkG6MfrSXBJ4Ufdk3AogQWyNS7x+3CivFedHKY8nwWpqpW4jV1DF5sd
         vSyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tDih3PYnn1rmwzgJnWarpiecICzuIRvMS90AZ5jPKpo=;
        b=ATd/Lt2hDFYyAzrTArzR2gY8jsH7xkQCtc9dBe6Xk0BF0qrGonpD2sNOfzp1Ol0ZYJ
         NJrvMAlPjbquiljLMrtl+BVxGHowSUL9nkFOpfqo8HhjK7YlblIDbcMOL3NwkTkYpCP3
         fIl4PIXda2JbxMHqcj9vZCErGmuphoh3Bv/PvSwK+TBF8TafF/5S0Vz2+zVi2GmQHDSH
         RTHIek/IhON02uAlz3+kRqRmd2ml6xJEvkTiV/4Egn12JJ62fL/OvhsZ0MLH3T+xV31+
         Qi4KCQ5XbxVL+PvK61s6uUBfjITmpKsR4fBMBnjg/TNzcprmX7yHfjMy8FAkUnSV3QyL
         hP2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mLHWVPc2;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tDih3PYnn1rmwzgJnWarpiecICzuIRvMS90AZ5jPKpo=;
        b=qeel88IBwgqsEMzpXCmoxBfYaZYUc1pC9A8heRivcNaWkoWQSdr+gLyJA6vKxppPvC
         qCbBA6LYEbsFQF3FtxGWXlOY2UZF00Aji4x7l3msf1lscw5CHyQnGQsutUjINoLByDqf
         l3qzAD4+XvOqLB6TAXCTEjDJPC2I79E234o7ybMta9gnpB7myNtEmUJB2peE8b/YV4KN
         K0/KkrZp29wkh92l+NUZR8XTJWfiGiLpq5F69FcRsnbDKJMH4XrI5bS/r3Yl86lH2pOH
         WPYuLgMoPDGkGGVYTATIW1EK2WmEuDWD4iliguenupFLmqJzULSSul3mmIILNxJLbe9L
         Ly1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tDih3PYnn1rmwzgJnWarpiecICzuIRvMS90AZ5jPKpo=;
        b=phtE2VtZuLfT5AXLEj87kTh+E7FNEa/IoLuEg53riUMmetHndK2dBpiI/MaiRjnZFl
         RsGzB63CaaZ152ZALxRlaxH4f91AgAsiErQha2chapreblduUfRYRNmuzdGpPGQ5EBcM
         pxaPDU2eSffoMLJ5B7wSvvnGxvVDYTIzixcw/7SnBb8/HdQKKumxPvU9b8ZDXDPYm7CL
         yKF90q6F6DdPsomz9D3dBZrwWVowEPxcyeDk1xCQc1ObFixJjSTWNdlsjuSekPostHdk
         hHbrOQu+2p2s9CAdXWZicIjmdjdb0zYPAZy4SCqwDjO1SaZj8B0BUqbDoiliPplTKeTX
         FZXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUy2QTAnkjAGsV69SebgYqo3jg1W3zDZ5qxL8csVz67Y1IGxKoA
	wOvsv2X1VaG8+5JVssvV9FU=
X-Google-Smtp-Source: APXvYqw8W/EJQ6bXEK5jGg2f6rEHqr37Je11rmojB+CTKH3lKJdLoK4GWID1HhT+9EZWHTr3elEWXg==
X-Received: by 2002:a9d:6d06:: with SMTP id o6mr34352016otp.225.1565749337649;
        Tue, 13 Aug 2019 19:22:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b803:: with SMTP id i3ls102073oif.4.gmail; Tue, 13 Aug
 2019 19:22:17 -0700 (PDT)
X-Received: by 2002:a54:4388:: with SMTP id u8mr3195966oiv.167.1565749337267;
        Tue, 13 Aug 2019 19:22:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565749337; cv=none;
        d=google.com; s=arc-20160816;
        b=kTkp7lgYtkIi1Atcip/SOwbl1dDfWmzOQM3/bc0m1yDtryOJwUDSn2XdaUAh2ndou0
         45Ci4pMD/95Eswld6ilfzoJWjBuKBRorw9yAMwJb4NRl/A/VXFq43+1JgB1dtsjD0KRC
         F1vt7vPdtuCb+vmyfVG4wFGxGneHdRFNVK1A5/5d32lOAtVWSokt1i73tqiuTTsawFKS
         lODHXd9W+fyk7YAh7+lWXMBfv7Dw0tMJWLBm5OkXfPusD2RlFQkOnrAFishQOxylDFoh
         XpHkT8TTKegubB5mXWgLxQRqdoOpd/uQxHm6cFbiolKRdJk1q/MlmjOWbPzOCIqlT1dS
         44dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=8BVuvw3t6MICKGaM59gUM2yEToQKCitDbig7bIPBipc=;
        b=mtXon3ri2B8B0RRaXtRShMgSdHbX9Gccqdh+p3dG+4RPEp3CPmRzJlSRFU5Maovv0J
         wMeLfMpLeRGP7bK6AgVFZrYM08RdZjSyFbO6c3q1e4sy3QS3bmVJMC1xFpK/X7fHasFz
         a3xAuPcb/T1mh8BMgHWpt4cxihoJmZCJtFWyqzfW0xRvwLZNsaYOUWLnK+iHoshfVQOP
         1ZUBKccW1HDEITL9AwxzWbj6/AJTKmOK40DKRo1ve7tYnOwH4FNmcenTAHnD0JFiypdG
         CZqrkUO60+FiUpq3c/DEgGdzAOwzE1/doJyhzCDRQR2REoYWucTBW8meaxw6N0lHdyRa
         uj3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=mLHWVPc2;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id w131si328030oif.2.2019.08.13.19.22.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 19:22:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id j7so34113353ota.9
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2019 19:22:17 -0700 (PDT)
X-Received: by 2002:a5d:9752:: with SMTP id c18mr82018ioo.22.1565749336873;
        Tue, 13 Aug 2019 19:22:16 -0700 (PDT)
Received: from localhost (c-73-95-159-87.hsd1.co.comcast.net. [73.95.159.87])
        by smtp.gmail.com with ESMTPSA id e22sm17331071iog.2.2019.08.13.19.22.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Aug 2019 19:22:16 -0700 (PDT)
Date: Tue, 13 Aug 2019 19:22:15 -0700 (PDT)
From: Paul Walmsley <paul.walmsley@sifive.com>
X-X-Sender: paulw@viisi.sifive.com
To: Palmer Dabbelt <palmer@sifive.com>
cc: Christoph Hellwig <hch@infradead.org>, nickhu@andestech.com, 
    alankao@andestech.com, aou@eecs.berkeley.edu, green.hu@gmail.com, 
    deanbo422@gmail.com, tglx@linutronix.de, linux-riscv@lists.infradead.org, 
    linux-kernel@vger.kernel.org, aryabinin@virtuozzo.com, glider@google.com, 
    dvyukov@google.com, Anup Patel <Anup.Patel@wdc.com>, 
    Greg KH <gregkh@linuxfoundation.org>, alexios.zavras@intel.com, 
    Atish Patra <Atish.Patra@wdc.com>, zong@andestech.com, 
    kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
In-Reply-To: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
Message-ID: <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
User-Agent: Alpine 2.21.9999 (DEB 301 2018-08-15)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: paul.walmsley@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=mLHWVPc2;       spf=pass
 (google.com: domain of paul.walmsley@sifive.com designates
 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
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

On Tue, 13 Aug 2019, Palmer Dabbelt wrote:

> On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
> > On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
> > > There are some features which need this string operation for compilation,
> > > like KASAN. So the purpose of this porting is for the features like KASAN
> > > which cannot be compiled without it.
> > > 
> > > KASAN's string operations would replace the original string operations and
> > > call for the architecture defined string operations. Since we don't have
> > > this in current kernel, this patch provides the implementation.
> > > 
> > > This porting refers to the 'arch/nds32/lib/memmove.S'.
> > 
> > This looks sensible to me, although my stringop asm is rather rusty,
> > so just an ack and not a real review-by:
> > 
> > Acked-by: Christoph Hellwig <hch@lst.de>
> 
> FWIW, we just write this in C everywhere else and rely on the compiler to
> unroll the loops.  I always prefer C to assembly when possible, so I'd prefer
> if we just adopt the string code from newlib.  We have a RISC-V-specific
> memcpy in there, but just use the generic memmove.
> 
> Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic
> Linux functions?  They're both in C so they should be fine, and they both look
> faster than what's in lib/string.c.  Then everyone would benefit and we don't
> need this tricky RISC-V assembly.  Also, from the look of it the newlib code
> is faster because the inner loop is unrolled.

There's a generic memmove implementation in the kernel already:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/string.h#n362

Nick, could you tell us more about why the generic memmove() isn't 
suitable?


- Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.9999.1908131921180.19217%40viisi.sifive.com.
