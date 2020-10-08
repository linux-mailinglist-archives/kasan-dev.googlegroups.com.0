Return-Path: <kasan-dev+bncBCF5XGNWYQBRB35Y735QKGQEKCEVQOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 92434287EFE
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 01:10:41 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id bb2sf4666447plb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 16:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602198640; cv=pass;
        d=google.com; s=arc-20160816;
        b=0xoh25bhCqMNORcO29o8hCOfk8rXW43NTmaI9cLQnWGuQB5siKP5aKZCiMS99nieHi
         POvysDfSKHipoooCaZFX/brb8ghpQBQgoDZ1cJBW3YbJumTUD7zEDPDEojLAk9XfiYDA
         +uYvt3CCtIjzFwrYBcomqlT2D87eU2Jwi4+I3DxOsZzB4eU2JNgzFKPAw1m3BYhKInEV
         X2S7v/CF2dgGQMH8llOa1nSaw49URKrq7Hk/y1xLP0N0w5FF91W1FUQIwXE46nUlz7TE
         dAYONdgPoXBwF3rCnwPkp19wlio9xza1WG3l3bL+eXr1Y9cY/Wm+/q6/+TeLbcat6EUN
         EPHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x7NkSsHiF+uuc9/L44gzUzfeCX9B3HGeUUGaYhkKrH4=;
        b=yVfH23ufJzCWIWgoqsZnesUHi6F2Z3D9BE4kvTrmUJzNO1vQeGRKpCFC6S/FI2L9O4
         3J1x+1TeecMmxRd/an+/zOrqvuKvCgGRoOSXOKhONLhhH19p4530oKAX3Xp3e4N+ETCW
         DJjl0v1AhjkEttB0IzbBeXTAO6SiMXzVgZiBp6TpnOArEWcyJgbxOzoU5gUvmJqIQ/PU
         OAHRGrfuNJtUBZl9uE+eG1/ZQeVsTe55kmyqXnBcfDFgNq/do5vvfkr/kgF66O+K+Kuj
         ZOIxvk4Cll11BwonqDU1u1riWnP5VqDmaToqQno13zis3Tw3ZEqhJfa/neESjqNg3oNb
         zRdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="m4LWGF/t";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x7NkSsHiF+uuc9/L44gzUzfeCX9B3HGeUUGaYhkKrH4=;
        b=D6POiTlWaRTkkSKxvQhnQ0XjF0xepnIV/3uk3+tU9V8oyOQSsxfKyRlh/c3GMiTvRc
         7O9KDIvLrEnNW23XWqvmZuxJhLf43aUOLN7WTylaOiou1AuOBeTR5rLMeDjprZmhgY8J
         cWghtNxaUPhiwMablCq7nTSsovP2swfE5uVPgEebLpIZGl6nsFXZ2PVV+nf6GZWprVWN
         boYh90cJs4LqbUH2+0AkMVXtmOVAA8df5BNxCP2kczBNWMaUKErEOhfrGKfCaSRfCYMx
         1SINWjsACXzpaTs0CLfewUqDisy2YUhedZ4eLtoDlbBtLRr2GzevWDsY7b4Rq/gAvDll
         qeJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x7NkSsHiF+uuc9/L44gzUzfeCX9B3HGeUUGaYhkKrH4=;
        b=kNUTRx1tczzK71JMvI9/2i5yPSszv1MXHjGYFR+FESdOTlcaqUDkWU4gVoAOhttKRS
         44AvWFiSWzvByV9JvRp/HaFCZFmly977BLABGllrsGizjG2MpDwzb8rBI/eH2n+KFiHy
         rVFikC0nvaYtDon8YHu6SmH/AZXSHVNYAAToixZKDaceKXUSL9WYZLOPUVqpH1Nsn1W8
         M1RrRc4p4eLR0PatZqzmDisfMfYRCcyYFZeZF/3sc511KR93oBOaopvybyKWUemWWcwo
         qx4/IYsv41e+qL7pqIzYHzmgRTwLn7m4np9kowv0nEhRNhBcNsWS4izWnKeXfP2s089C
         Gs0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UDTiScoXhLtFofe0RvvPlA4fkZ3BVL3Ez+pu2cIl3EGDoxO8j
	vnTbckF41/+Uo68XikgZLzY=
X-Google-Smtp-Source: ABdhPJy+ScyLsoYO7GXMru1D2dVfM42Jpo7a16HHF41aJWGyeNGusy6Pcoi+wxZQvX6sOFik5fltcA==
X-Received: by 2002:a62:7716:0:b029:155:2e1d:a940 with SMTP id s22-20020a6277160000b02901552e1da940mr7850703pfc.56.1602198639853;
        Thu, 08 Oct 2020 16:10:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5064:: with SMTP id q36ls2665652pgl.0.gmail; Thu, 08 Oct
 2020 16:10:39 -0700 (PDT)
X-Received: by 2002:aa7:9607:0:b029:155:2b85:93f5 with SMTP id q7-20020aa796070000b02901552b8593f5mr7782057pfg.36.1602198639302;
        Thu, 08 Oct 2020 16:10:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602198639; cv=none;
        d=google.com; s=arc-20160816;
        b=qkrM3l4cE6Z1wYKvc+UPrxtgl/js94e13LzfBYjf297vzX9JvCy9e9yxa6PJoPg2sk
         AuoyEnOWUvEQ0spyVopoui26sK23xK9rS0uZny+q49ZnM5u/H2fnpr+OLzK6mBPNrqH9
         CiEnYccM2ihaQjaekke9ZUQ10zsN1dGxExp5F5r4URhHOcOEcJlnIOiy27Fn9KswimW+
         W0kTTdLLhoyPKqlhg9EDmatmXb8YkQdAZ+UJodfhYdQcxHt3FxPs0XP+zZnEAzOd442y
         bdoUjLwdCCS5EUMql1knXrwAMeNHk927sItUI77RgKfjJfpGPjk/fFc0RmSBUBfReD+6
         ujpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=huNoRIdSFpI9osYj0Zanh/sVIIaopm6n5nRrz69OQbw=;
        b=QqajvNnpT0NxcC38ypfYTH8ceM1FuKmuVNvUTzRiomBeEoOlx0IabKbjzv+jYPzIu1
         jQlEE+g6A2CORPBC9LpnEeVUOQ2lZKtO5+qbiZNQU1D8CG3Wf5ssw3SfuqlvIyHYbnLj
         Myifu+xZcHC4Fgp2gXVjiAn3Bl9bnuexTsIijh618WOnNWupl0fOaUupq588x/x1FkVO
         P6f46Ub1LhFDXE8XGfV8qixVLjHf90AsKdcS6mJdKIDaPZpG4hdNM08FaIVKaSz8aeaT
         vAjTXbIwl7j4fnLr5hF5jjRBD3jvNxu1ZIh+1tHu7vP62K1cff5GE5ZwIojF3vGi+isL
         LndQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="m4LWGF/t";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id m62si522702pgm.2.2020.10.08.16.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Oct 2020 16:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id o25so5610586pgm.0
        for <kasan-dev@googlegroups.com>; Thu, 08 Oct 2020 16:10:39 -0700 (PDT)
X-Received: by 2002:aa7:94a4:0:b029:151:d786:d5c2 with SMTP id a4-20020aa794a40000b0290151d786d5c2mr9273480pfl.50.1602198639047;
        Thu, 08 Oct 2020 16:10:39 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id w187sm8143383pfb.93.2020.10.08.16.10.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Oct 2020 16:10:37 -0700 (PDT)
Date: Thu, 8 Oct 2020 16:10:36 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Pekka Enberg <penberg@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Christoph Lameter <cl@linux.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
Message-ID: <202010081608.E1401C067@keescook>
References: <20200807160627.GA1420741@elver.google.com>
 <CAOJsxLGikg5OsM6v6nHsQbktvWKsy7ccA99OcknLWJpSqH0+pg@mail.gmail.com>
 <20200807171849.GA1467156@elver.google.com>
 <CAOJsxLEJtXdCNtouqNTFxYtm5j_nnFQHpMfTOsUL2+WrLbR39g@mail.gmail.com>
 <CANpmjNNhG4VuGq2_kocsTD3CnCv-Y4Kvnz7_VuvZ9Eug+-T=Eg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNhG4VuGq2_kocsTD3CnCv-Y4Kvnz7_VuvZ9Eug+-T=Eg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="m4LWGF/t";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Aug 17, 2020 at 08:31:35PM +0200, Marco Elver wrote:
> On Fri, 7 Aug 2020 at 21:06, Pekka Enberg <penberg@gmail.com> wrote:
> ...
> > Yeah, it reproduces with defconfig too, as long as you remember to
> > pass "slub_debug=Z"... :-/
> >
> > The following seems to be the culprit:
> >
> > commit 3202fa62fb43087387c65bfa9c100feffac74aa6
> > Author: Kees Cook <keescook@chromium.org>
> > Date:   Wed Apr 1 21:04:27 2020 -0700
> >
> >     slub: relocate freelist pointer to middle of object
> >
> > Reverting this commit and one of it's follow up fixes from Kees from
> > v5.8 makes the issue go away for me. Btw, please note that caches with
> > size 24 and larger do not trigger this bug, so the issue is that with
> > small enough object size, we're stomping on allocator metadata (I
> > assume part of the freelist).
> 
> Was there a patch to fix this? Checking, just in case I missed it.

Hi! I've finally carved out time to look at this, and I've figured it
out. My prior redzoning fix was actually wrong; I'll send a patch to
fix it harder. In the meantime, I've also discovered that the redzoning
code wasn't safe for sizes smaller than sizeof(void *). This oversight
is, I think, what caused me to incorrectly handle the changed offset the
first time. :P

Anyway, patches incoming...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202010081608.E1401C067%40keescook.
