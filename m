Return-Path: <kasan-dev+bncBCCMH5WKTMGRB74FVGLQMGQEWQYQ4OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C9DB588990
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 11:42:25 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-10e7667b972sf5604788fac.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 02:42:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659519743; cv=pass;
        d=google.com; s=arc-20160816;
        b=E++oPt1DN1vYPBYLWWHFAobfa3rl7VNVDtOhf3GEVWe5MxTej13NeQFsg0ggupFRAy
         fUCHPy/zJ8ct7UDCnLhPN7fNthQ1Muv2+lRzj1PrV187X21935lvr6eLDTbbcl/+DfoQ
         In9O5As/sybCED13F2JBfqmXrFExtn0228MQQbFHrTwQmSUdhQcjcOvwLcyeWfWbvQJV
         3/qb0LalUyZIjwdAm9uZhz9gYz7hMioQiEJ4oMNE3YO3FkLsGD69pVhiRe1d8yq+vAxu
         +GyJT77MY0Sn4ypQ43uVafxaTgmzMTslZQdrlImMePSJNmJuAm7lCTAH9t7STP2H7IED
         IKrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GFATrdzWSL9kc6g5CnOBDIr640uomJi/obgr5e36UPQ=;
        b=r8jVY6vCa8IBWG97wMrIpydKKVEiVGAsfSRdCeSl3TRZeOOmXhxMQJZJdCe7lPY1VN
         zCAw9dGam8FUQKHI5eSxAs5XhJX1re76yRNKzVCHT2O4zzYmxIMXu+9hclWHnJN9H1yN
         KCqKbmQhJBoj7lMrH4Y60pDPx9N7yIxC7Pp22EzhLR1ckMLvwAmlQJoQnNqXGPElV+TU
         aVTQFQL1bgZCd3VJbOeSib1bkYVhF7vJp1mcH5VNH7gP/PAzBnQYumQhA4ZyLV+bQJxM
         PTLtujPCYVCCDHDXHXpPihfVFulLZzLNvhi/rrov9zcD06PMrpu8/tHJ96QQbIoRBUfC
         4y4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UW16xIvr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GFATrdzWSL9kc6g5CnOBDIr640uomJi/obgr5e36UPQ=;
        b=d5yVbC01LUS73DTdCarE5AkRx2JJ4EHLRdfJgaxhcMKenhI4In1B5nu4Zm/viCuofW
         qguX7nWZpEfMS1UHz8gj/Jy8OEJGOKREI3l76g+2kZf9ar+ZMzjDlF6iTCoTQXI0tmCm
         DEBpHrJi3f+97sav35Sl9QRDKHSuhixFFonO1HHJLPdSTWvAztflHufSsWuYIvZ7yACd
         FwhoklEIScS1RG2LkYe9TQ1nLToHgg0i0IM1r6vEbBRzfD5hf8vr+uFeBjJdI/abCidX
         Rvr7q7rTyKkxN7QfzQ78gU/b3nBRrGuTqNlM2DcRwGyiybKGx24/62+1lPmE9QO+1ghB
         9otw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GFATrdzWSL9kc6g5CnOBDIr640uomJi/obgr5e36UPQ=;
        b=rUbywElN5N9+1bjHz3ydOoAcqOUCX+3bJs7zSO57ti5wJTKK+nd8FEVtK1DQlLJP0g
         e0WLZHuAG03FwbjcGdRI39sKEzoOiEn9t1ediqWO36G3IFcNUehxpuD5SGluGBBvdZcV
         XqHUPUfRnKCJFOsAze5PezvhqKeiOjPROjpYf4hbpBlrEZHm6OM5WNB3psD38FhfKS4a
         LzyCBEyH4LHKYmBLBtVPT4c3xpQrJs8IWYeG82NFhSwMmlRsQlUMeNBTpKTctcnQdXjN
         mua2A9bk0U0pEVGAkFZgT8EDmgOJdePSMiEzKSXP84XKMG7cj9OcQzqnwYnkY3r+7SGA
         LIcg==
X-Gm-Message-State: ACgBeo29WGd6YbKnUnJt8bc5Y8o1Qs+WP2xGPDZ9WSllxijT8KGGNQl5
	QLdjL66nJlz8STwyg7vgjLo=
X-Google-Smtp-Source: AA6agR5Lnyis6/V2tqcga+ImibFhC9UiC0ojGTSMMgD/0+yRf3deLVF9U+oiv6ZFxLlQbpvREWMROQ==
X-Received: by 2002:a05:6870:b427:b0:f2:2dfd:e895 with SMTP id x39-20020a056870b42700b000f22dfde895mr1468471oap.225.1659519743677;
        Wed, 03 Aug 2022 02:42:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:31d5:b0:10e:dd6c:2ddb with SMTP id
 x21-20020a05687031d500b0010edd6c2ddbls2612971oac.8.-pod-prod-gmail; Wed, 03
 Aug 2022 02:42:23 -0700 (PDT)
X-Received: by 2002:a05:6870:9a17:b0:e9:3d1:f91a with SMTP id fo23-20020a0568709a1700b000e903d1f91amr1522752oab.44.1659519743207;
        Wed, 03 Aug 2022 02:42:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659519743; cv=none;
        d=google.com; s=arc-20160816;
        b=BT1ycuu0jCGDm02Io/+mxmCj4ftHBiJKsedxLx5U9bF01LnexpZAPUJp9L3Fkp/zIC
         ASw3qKK4jLU8AFHxII4XieGQMCLFmOZEizC9QB0zXnc7v4GbSTg9XO6r0ArA8U4gBpCh
         TzTOdcxdUBnQaWOz1tNELPNSkb3R9Z9d+P8vnmAQPvxAIeJQYfAdeMXNcs1dxSycCLzr
         L5vS8yZ172mpcVjEYqCCZsh8AILM44aVmaLYNeWnKfQSA2yCieUeOL/eGmIyDCRPSHPT
         lxYBTR0JAtCdzPNEf6V7MVlFsfevYMujA1vm4PjT74PG3W0IQs5WTupMpB2VL1852qEG
         VE3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/5J/hTicAQKvIdTCsN8vIr3eGdVqz6oWNgR8PbCUFZ0=;
        b=FThOyrSAujl1WAIWW9WoK9tvxL5Z3xRggvuj7ec+acCWTpyDGy/AMJ+tu9B/4Lmig4
         91IuPU/YXUdHoxtpGhmkY07mS+8pXBJRFPYZdAXbZ14nLsA27swKVcC9WZJp4HyG+ODk
         UoKHJdlwUuBqdVY9rDxsnaJznwMg8TL6LyFdzbzEPFsE3udlkDYHI2oCbfMS91IdBl2Y
         KQ1+vmJ9CUggoGZmIbheeq+7N0XYsfpKc617QXAJ+yfrlN6+88y0iqBX5qtYCiYta5Tu
         ZJol9EHg7F5mbZp+IJVyWIHT88jDfHVFaJZrL5CLcgnn06MSMlQr+EKfTwSNLZGYayun
         ISgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UW16xIvr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id d14-20020a4aeb8e000000b0035e8a81e5fcsi734155ooj.2.2022.08.03.02.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 02:42:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id y127so27507001yby.8
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 02:42:23 -0700 (PDT)
X-Received: by 2002:a25:d7d3:0:b0:671:899b:eafc with SMTP id
 o202-20020a25d7d3000000b00671899beafcmr18510665ybg.485.1659519742790; Wed, 03
 Aug 2022 02:42:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
In-Reply-To: <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 11:41:46 +0200
Message-ID: <CAG_fn=UToPvi8-1puuCS95o1V36MkAwFyQKFgp0AxBROcNgfKg@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Marco Elver <elver@google.com>, Dan Williams <dan.j.williams@intel.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UW16xIvr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b32 as
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

(+ Dan Williams)

On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
> >
> > KMSAN adds extra metadata fields to struct page, so it does not fit into
> > 64 bytes anymore.
>
> Does this somehow cause extra space being used in all kernel configs?
> If not, it would be good to note this in the commit message.

I actually couldn't verify this on QEMU, because the driver never got loaded.
Looks like this increases the amount of memory used by the nvdimm
driver in all kernel configs that enable it (including those that
don't use KMSAN), but I am not sure how much is that.

Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?

>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUToPvi8-1puuCS95o1V36MkAwFyQKFgp0AxBROcNgfKg%40mail.gmail.com.
