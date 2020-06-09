Return-Path: <kasan-dev+bncBCVJB37EUYFBB4NW7X3AKGQE3DIFX6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id DB8A01F3741
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 11:50:42 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id t13sf14158561plo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 02:50:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591696241; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yqez8cZ1ldzpL6C9Hgs7TeMBXrFZXnLtfltmETJsZ24LHyaIsVjRMeL5PlVEWcIgGX
         NIsbfrS1fOD8K7IrGOAlB9wby8OkNjUuqUrsI+AJM6rAzIiCAz2nKOz17dZx6f2i7Htd
         RDIm80+/JNhbxIPBGoGjauz9gLJ5JqhSn3s2osmTmDP7EDxXUADdf0jccqyz+/QUJXka
         eXvh16IBdBJYmLw+hmRNSIqgYTXtnTcZOJAv64Ih2juMldRoSlJrKrGQcFqtAv+m+UtD
         F0OVlFo9cGTfl/U8jjmK8GCAtaNsLZUvYy4qP4VyD2h5l9gOY028MNOf0+hobQbY6RXK
         XngA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:reply-to:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=UC0DLfxFFLkDFKe/0Vh3QZm6Pf4fsa9piNOAcxUp/08=;
        b=felD0Za2QM/G/Ux2nUbZyX2ery6ylaWIi28t9fgSZcONBQ3pWkHKKluonTNp5lfvwg
         fDiBWpSlnwtiyJdijC2LojCs3916CzQc5QqFJpeXYwD/+ZrBbrVFJ3GE7r/Yotc/j/2L
         L5iYqerT+OR/qr2gWUqyvgoRog6Jb9bHiR4pqRqkO/Hr1YbSpAIP6H6LDwEcEqZ6pE9h
         cuxRUMC4MB8F2gUwHVVPVqvE/F9wglZPrhMLHfbIfAeCz74WfVDCEgeEKfdxFFuLnycJ
         cSmbg49ShUGhSNI1RLVqkZ76vtMWcRfknDQ3t0P+jz+DffFOE7CYCRskSoHGQ5/haXgs
         RDFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N6lble2A;
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UC0DLfxFFLkDFKe/0Vh3QZm6Pf4fsa9piNOAcxUp/08=;
        b=YWa0qWHyHj5win6u9A8rWbY1X8hTXyIouWpke8KtO5j1OZkQgydtTjRpmu5LMhW+H9
         RIqtbQHTES8+9TYQKp/EVUTL1lD3hqWKLAbBJU/LnCW5XpbPM4yw2rRwdHPTVKSnAE+g
         dDHqTi2Hs04K549fgBVvuF/3e/dUs2gyDdG4CWtWpV/WDFQt4YT6pP6hw+RyutIChBxu
         PuHJwfwZxHGDcJtpjdAo4yTkvniqakHSavCwapQ+YY1JBIbBnHqAlnsMKV3jHip6/1kC
         qin+iRApwJ9wtEE6zC5Hh6p7YnETy7DVlRd9Nd4a/gjzES9AF7IFSuH3l5be3RAH3Gqk
         enNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:in-reply-to:user-agent
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UC0DLfxFFLkDFKe/0Vh3QZm6Pf4fsa9piNOAcxUp/08=;
        b=S2xU0PkeSbCCDH0EAuRAMu1O658JY//eCJRMjLo7serX7MjsfuuJPb9tJJnj28EhVG
         qIghR6ePVkrgTpvDfpCPs3pGkLwYkNuizXHhOIdd9DZZ7aPBFnFekZfVerAXJfnRdnnC
         jrFbnkA2HKOPSjaNuklPyYpEDYAbGJHdY/qwVKH9hFNR/gWwayzy6Y8i/JjaxqS6b834
         yFSfclWrMwt1B+omL0K1sRJ4yI7iFQrg4MX6i6Qn1H6IIt7FuanfoHbbpxaPI969VXxX
         cyB5S7kyKT8cyX8sHjygXZURPppr4g/Uqeerr9b1UOXiMjtWNj1SlPQvBrzCDSmT/zjb
         IaEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319VySMhAwMcsZqM6/yzL3ROsJPWLPjCVsGOlw/0c+t34X+04rP
	IlLoxFgRbEbyK0AbjzNEmOo=
X-Google-Smtp-Source: ABdhPJya9h5mze0ZgJRO+JSIwPjYyNF52fFnU7XQU7kBEqNsdmkXRn5NMisf92jqUvSo+VG7kvft/g==
X-Received: by 2002:a17:90a:25cc:: with SMTP id k70mr4095323pje.174.1591696241355;
        Tue, 09 Jun 2020 02:50:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7143:: with SMTP id g3ls1250161pjs.1.gmail; Tue, 09
 Jun 2020 02:50:41 -0700 (PDT)
X-Received: by 2002:a17:90a:c250:: with SMTP id d16mr3869609pjx.60.1591696240942;
        Tue, 09 Jun 2020 02:50:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591696240; cv=none;
        d=google.com; s=arc-20160816;
        b=HDgEYhihNH+oBzZPo5YSkmqralEL+lR+foDQL2tBHyWSJmDIlda/oSnNzODHLb6Zzr
         e3RZQsKpEl3/c9xMS+Ur+Cg3nA0b9SDbr44yJT8KW97RcByHPxx1T5qtRaVtXyJbylRe
         5rKgqumrigIEtVCmju80v8mS2MZJ1hUfdzKPvB/8iFmqeoLLowcxMKzURLGjKDhkTdeK
         ZBoVluGGkXjrfCy2uUBucN39OFBZtKlBrJIuHn2nhIBBl8oojtzVbOSutL5PbgUMHDLe
         nfv1NndhEFbOf5Jk07GZWkAwWz+q4pkinR+T9WzvnCEiPDKSyG26hWg5/kYFQbjO8K5a
         r6Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:user-agent:in-reply-to:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=T9Jv90EGNWMikVBKPI1gGirVBangAIYT1bTwNnc0D4E=;
        b=VUtVkA6jf866xwoL3MKe8JOrP0YGDhElqwkE5xNQeSt/zyeRTtLysbPe+uB1dTaYAD
         Z0UaEYb1fiB9wsbsSdEusSQRFjhhPIirADm5YRv7+YFqompBL3wgWMPmHhtru6aU+yqt
         CqtFG0wOcBsIte1f5GlvIV0Wytrh5NxXGtvHMM79N3pity0MtsdSg5LdyiLmDQtnAnOF
         ydMo5s898fVTvlBNV864uSsqWu6NCyFOqJJLjhW5b00DXCz5rozhJyg0+EAOVttDFPG/
         /IfsCZypW0fwTImrrOWv+yHSLdUTH99UNN7yiKBu1U4CEV4HJ6qMapDdHkwRGVZ0XtpQ
         KLHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=N6lble2A;
       spf=pass (google.com: domain of jakub@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id v197si772294pfc.0.2020.06.09.02.50.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 02:50:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-31-1WltoHbpN_asrmzfa1TZAQ-1; Tue, 09 Jun 2020 05:50:38 -0400
X-MC-Unique: 1WltoHbpN_asrmzfa1TZAQ-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id BA417107B265;
	Tue,  9 Jun 2020 09:50:36 +0000 (UTC)
Received: from tucnak.zalov.cz (ovpn-112-94.ams2.redhat.com [10.36.112.94])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 1F6FB60C47;
	Tue,  9 Jun 2020 09:50:35 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.15.2/8.15.2) with ESMTP id 0599oWEk008211;
	Tue, 9 Jun 2020 11:50:33 +0200
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.15.2/8.15.2/Submit) id 0599oVMN008210;
	Tue, 9 Jun 2020 11:50:31 +0200
Date: Tue, 9 Jun 2020 11:50:31 +0200
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: gcc-patches@gcc.gnu.org, mliska@suse.cz, kasan-dev@googlegroups.com,
        dvyukov@google.com, bp@alien8.de, Dmitry Vyukov <dvuykov@google.com>
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing
 volatiles
Message-ID: <20200609095031.GY8462@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20200609074834.215975-1-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20200609074834.215975-1-elver@google.com>
User-Agent: Mutt/1.11.3 (2019-02-01)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=N6lble2A;
       spf=pass (google.com: domain of jakub@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Tue, Jun 09, 2020 at 09:48:34AM +0200, Marco Elver wrote:
> gcc/
> 	* params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> 	* sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> 	builtin for volatile instrumentation of reads/writes.
> 	(BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> 	(BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> 	* tsan.c (get_memory_access_decl): Argument if access is
> 	volatile. If param tsan-distinguish-volatile is non-zero, and
> 	access if volatile, return volatile instrumentation decl.
> 	(instrument_expr): Check if access is volatile.
> 
> gcc/testsuite/
> 	* c-c++-common/tsan/volatile.c: New test.

In general looks ok, just some minor nits.

> --- a/gcc/params.opt
> +++ b/gcc/params.opt
> @@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
>  Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
>  Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
>  
> +-param=tsan-distinguish-volatile=
> +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param Optimization

Do we need/want Optimization here?  Optimization means the option is
per-function, but to me whether you want to distinguish volatiles or not
seems to be a global decision for the whole project.

> +Emit special instrumentation for accesses to volatiles.
> +
>  -param=uninit-control-dep-attempts=
>  Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1000) IntegerRange(1, 65536) Param Optimization
>  Maximum number of nested calls to search for control dependencies during uninitialized variable analysis.
> --- a/gcc/sanitizer.def
> +++ b/gcc/sanitizer.def
> @@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "__tsan_read_range",
>  DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range",
>  		      BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
>  
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_read1",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_read2",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_read4",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_read8",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_read16",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_write1",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_write2",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_write4",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_write8",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> +		      BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)

This last entry is already too long (line limit 80 chars), so should be
wrapped like:
DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16,
		      "__tsan_volatile_write16", BT_FN_VOID_PTR,
		      ATTR_NOTHROW_LEAF_LIST)
instead.

> --- a/gcc/tsan.c
> +++ b/gcc/tsan.c
> @@ -52,25 +52,41 @@ along with GCC; see the file COPYING3.  If not see
>     void __tsan_read/writeX (void *addr);  */
>  
>  static tree
> -get_memory_access_decl (bool is_write, unsigned size)
> +get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
>  {
>    enum built_in_function fcode;
>  
> -  if (size <= 1)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE1
> -		     : BUILT_IN_TSAN_READ1;
> -  else if (size <= 3)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE2
> -		     : BUILT_IN_TSAN_READ2;
> -  else if (size <= 7)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE4
> -		     : BUILT_IN_TSAN_READ4;
> -  else if (size <= 15)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE8
> -		     : BUILT_IN_TSAN_READ8;
> +  if (param_tsan_distinguish_volatile && volatilep)
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
> +            : BUILT_IN_TSAN_VOLATILE_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE2
> +            : BUILT_IN_TSAN_VOLATILE_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE4
> +            : BUILT_IN_TSAN_VOLATILE_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE8
> +            : BUILT_IN_TSAN_VOLATILE_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE16
> +            : BUILT_IN_TSAN_VOLATILE_READ16;
> +    }
>    else
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE16
> -		     : BUILT_IN_TSAN_READ16;
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE1 : BUILT_IN_TSAN_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE2 : BUILT_IN_TSAN_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE4 : BUILT_IN_TSAN_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE8 : BUILT_IN_TSAN_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE16 : BUILT_IN_TSAN_READ16;
> +    }

The above gets too ugly.  Please use use instead:
  enum built_in_function fcode;
  int pos;
  if (size <= 1)
    pos = 0;
  else if (size <= 3)
    pos = 1;
  else if (size <= 7)
    pos = 2;
  else if (size <= 15)
    pos = 3;
  else
    pos = 4;
  if (param_tsan_distinguish_volatile && volatilep)
    fcode = (is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
		      : BUILT_IN_TSAN_VOLATILE_READ1);
  else
    fcode = (is_write ? BUILT_IN_TSAN_WRITE1
		      : BUILT_IN_TSAN_READ1);
  fcode = (built_in_function) (fcode + pos);

We have other code that already relies on certain *builtin*.def ranges being
consecutive.

> @@ -204,8 +220,11 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
>        g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
>      }
>    else if (rhs == NULL)
> -    g = gimple_build_call (get_memory_access_decl (is_write, size),
> -			   1, expr_ptr);
> +    {
> +      builtin_decl = get_memory_access_decl (is_write, size,
> +                                             TREE_THIS_VOLATILE(expr));

Formatting, space between VOLATILE and (.
And perhaps you don't need to use the builtin_decl temporary, just:
    g = gimple_build_call (get_memory_access_decl (is_write, size,
						   TREE_THIS_VOLATILE (expr)),
			   1, expr_ptr);
would be fine.  The reason to use the temporary in the other cases is that
it gets too long and needs too much wrapping.

Ok for trunk with those nits fixed.


	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200609095031.GY8462%40tucnak.
