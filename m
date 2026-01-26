Return-Path: <kasan-dev+bncBDUZLLUDZUPBBI5P3PFQMGQEC4RQ3NA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id Cl6+IabXdmnQXgEAu9opvQ
	(envelope-from <kasan-dev+bncBDUZLLUDZUPBBI5P3PFQMGQEC4RQ3NA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 03:55:34 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 06DA78398A
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 03:55:33 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-40438351feesf6360078fac.1
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jan 2026 18:55:33 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769396132; x=1770000932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=insTqA3e7rk5kvuXsl1N0Uw2GVFaZI/7pJ37ivCttJQ=;
        b=TlkfY3EeLVlN6QF6aNS49AXIoI4yAn7k1exTy8V2PRY5VTTfmx+hOtexMDEBJK0JrR
         eT5lgTaA/o0jjAR36jyhu7dCtRWxJD95J8nHk/9V3ISNEhsMzIiDWmlynYUzasIV+GRU
         ziVeVUZlluw4cqT+dSH5BRqgcszXGWPbuAI4TR7dXTOkSweb9UEzK0XEYuxNBn0lRBUc
         LmKNXvN52iqTwv7/2vKSvBaQ8A0giyauW+r1kvObJ7/iziKOOMnXIj/TQbkcxgKFg8Y5
         aWdiwh0Yiq4ejMcxHTbdeNjKf+robGmUCMp6g4AeeEU/apIRnCRqbtu4m28ehPpSV84k
         tI/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769396132; x=1770000932; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=insTqA3e7rk5kvuXsl1N0Uw2GVFaZI/7pJ37ivCttJQ=;
        b=mZ9gi2jFm009Hgb1+c2qaPTMhJEfjTfZe/SUZGV7UsFti5Wftlq9I5asJRf+eomIxv
         1SzZO206cmezGqLp+5pZebSzGyfVM3/CfkOjKgPc1QhF9KvGtiQN/gb0Ax44QydEraZe
         FPC58Y8Ik9PKFQK2DkwtTh20eR4OUm3j884m8VOvLcjTfGioBfvouidlK8s1NkVIoZSy
         KjmVCFFfu8B/bEZio8MW97ef5BnddUveaWy65vIiA6aLrh4U2G5VDBnQW9Lf8LNvnY8k
         aLDJVl6wCUsgH8tlklZYTjk6SEcfGW2CPpDq9Oe7t3IAeTccDIQQL472p8nzFuL5/Oig
         ZQ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769396132; x=1770000932;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=insTqA3e7rk5kvuXsl1N0Uw2GVFaZI/7pJ37ivCttJQ=;
        b=D7D2LtPlwHAhtO7WOnSdEgoAHeqjNtiF1p8tJBr00570vZCbGKFzaIjqVRmsRZTY77
         LopQF8qfLjIV61sqaoyfDT7fDgZGWmfArykQJBeTscmgI/yMCIcywbVXocEUMU4Q1ucN
         vM6iFpTjDcHF0RUR2GiTj2VKZXb6aVCd2G33WIrxSx7yNqQ2SSPgbV0GbWna2lUVtOjY
         o8qNWCUYvYkDbxJK039rWQ2aO8HVVgp8DDanK740lYvzpQCL/Ydbh0A6oVG37NqZxrrK
         Qhed41p2m265aNJT6GEpKhtw8v/jfi33Vd+WOjnHLxlBjpbrRy+1j/O7HPc8O4HeT17E
         kiOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWZRlOYK2n+VkbOaDI1eUZK3WmhLdtvCDRuBm97Fvd4qraGP0Ij5n38pzHmnekBjgdjqeA1XQ==@lfdr.de
X-Gm-Message-State: AOJu0YxDH98lUCEbgg69H7MBGjYIxF/OI/Fxibuzhj0xVq/ChxisUwIq
	khy/7jr/gO0l8EfN5yAXD16ER3+NaaO19ngch83rDw7Nefq15XDxkD58
X-Received: by 2002:a05:6870:45a0:b0:404:2c03:e408 with SMTP id 586e51a60fabf-408f812ef26mr1753618fac.37.1769396132032;
        Sun, 25 Jan 2026 18:55:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HmEOuElRTHaiZ+uNJaX47FencVGYButActoPkeg6xADg=="
Received: by 2002:a05:6870:658a:b0:3e8:4817:7a50 with SMTP id
 586e51a60fabf-4088207df92ls1910774fac.0.-pod-prod-05-us; Sun, 25 Jan 2026
 18:55:31 -0800 (PST)
X-Received: by 2002:a05:6808:87ce:b0:45e:e15e:4ab2 with SMTP id 5614622812f47-45ee15e4d18mr729594b6e.45.1769396131076;
        Sun, 25 Jan 2026 18:55:31 -0800 (PST)
Date: Sun, 25 Jan 2026 18:55:30 -0800 (PST)
From: Lizbeth Chodash <acc9533@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <18d5679b-a386-4a0c-bccc-89e3f478f037n@googlegroups.com>
In-Reply-To: <20260123084404.GF171111@noisy.programming.kicks-ass.net>
References: <20260119094029.1344361-1-elver@google.com>
 <20260120072401.GA5905@lst.de>
 <20260120105211.GW830755@noisy.programming.kicks-ass.net>
 <20260122063042.GA24452@lst.de>
 <20260123084404.GF171111@noisy.programming.kicks-ass.net>
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_526638_1050013267.1769396130422"
X-Original-Sender: acc9533@gmail.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [0.79 / 15.00];
	CTYPE_MIXED_BOGUS(1.00)[];
	MID_RHS_MATCH_TO(1.00)[];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	MIME_GOOD(-0.10)[multipart/mixed,multipart/alternative,text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	MIME_TRACE(0.00)[0:+,1:+,2:+,3:~];
	TAGGED_FROM(0.00)[bncBDUZLLUDZUPBBI5P3PFQMGQEC4RQ3NA];
	TO_DN_ALL(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_ONE(0.00)[1];
	ARC_NA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_FROM(0.00)[gmail.com];
	FROM_NEQ_ENVFROM(0.00)[acc9533@gmail.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,googlegroups.com:mid,mail-oa1-x38.google.com:helo,mail-oa1-x38.google.com:rdns]
X-Rspamd-Queue-Id: 06DA78398A
X-Rspamd-Action: no action

------=_Part_526638_1050013267.1769396130422
Content-Type: multipart/alternative; 
	boundary="----=_Part_526639_1828443150.1769396130422"

------=_Part_526639_1828443150.1769396130422
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

If you lost your BTC or ETH, I will help you to recover your funds. I will=
=20
charge 10% after your recovery. Whatsapp me at +1-646-914-3655


On Friday, January 23, 2026 at 1:44:13=E2=80=AFPM UTC+5 Peter Zijlstra wrot=
e:

> On Thu, Jan 22, 2026 at 07:30:42AM +0100, Christoph Hellwig wrote:
>
> > That's better. What would be even better for everyone would be:
> >=20
> > mutex_prepare(&obj->mutex); /* acquire, but with a nice name */
> > obj->data =3D FOO;
> > mutex_init_prepared(&obj->mutex); /* release, barrier, actual init */
> >=20
> > mutex_lock(&obj->mutex); /* IFF needed only */
> >=20
>
> This is cannot work. There is no such thing is a release-barrier.
> Furthermore, store-release, load-acquire needs an address dependency to
> work.
>
> When publishing an object, which is what we're talking about, we have
> two common patterns:
>
> 1) a locked data-structure
>
> 2) RCU
>
>
> The way 1) works is:
>
> Publish Use
>
> lock(&structure_lock);
> insert(&structure, obj);
> unlock(&structure_lock);
>
> lock(&structure_lock)
> obj =3D find(&structure, key);
> ...
> unlock(&structure_lock);
>
> And here the Publish-unlock is a release which pairs with the Use-lock's
> acquire and guarantees that Use sees both 'structure' in a coherent
> state and obj as it was at the time of insertion. IOW we have
> release-acquire through the &structure_lock pointer.
>
> The way 2) works is:
>
> Publish Use
>
> lock(&structure_lock);
> insert(&structure, obj)
> rcu_assign_pointer(ptr, obj);
> unlock(&structure_lock);
>
> rcu_read_lock();
> obj =3D find_rcu(&structure, key);
> ...
> rcu_read_unlock();
>
>
> And here rcu_assign_pointer() is a store-release that pairs with an
> rcu_dereference() inside find_rcu() on the same pointer.
>
> There is no alternative way to order things, there must be a
> release-acquire through a common address.
>
> In both cases it is imperative the obj is fully (or full enough)
> initialized before publication, because the consumer is only guaranteed
> to see the state of the object it was in at publish time.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
8d5679b-a386-4a0c-bccc-89e3f478f037n%40googlegroups.com.

------=_Part_526639_1828443150.1769396130422
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div style=3D"inset: 0px auto auto 0px; position: absolute; overflow: hidde=
n; z-index: 1; display: flex; flex-direction: column; width: 1536px; height=
: 695px;"><span role=3D"main" style=3D"contain: style; display: block; over=
flow-y: auto; z-index: 1; height: 631px; margin-left: 280px; transition: ma=
rgin-left 0.25s cubic-bezier(0.4, 0, 0.2, 1), visibility linear;"><span sty=
le=3D"contain: style; display: block; height: 631px; overflow: hidden; z-in=
dex: 1;"><div style=3D"display: flex; flex-direction: column; height: 631px=
; margin-inline-start: 16px; position: relative;"><div style=3D"overflow-y:=
 auto; outline: none;"><div role=3D"list" aria-label=3D"Can you Recover if =
Your Crypto Wallet is Lost, Hacked or Stolen? /Call +1 805 591-4143"><span =
tabindex=3D"0" role=3D"listitem" aria-expanded=3D"true" style=3D"border-bot=
tom: none; padding-top: 8px; padding-left: 0px; border-left: 2px solid rgb(=
77, 144, 240);"><div tabindex=3D"-1" style=3D"outline: none;"><div style=3D=
"display: flex;"><div style=3D"flex-grow: 1; min-width: 0px;"><div role=3D"=
region" aria-labelledby=3D"c702" style=3D"margin: 12px 0px; overflow: auto;=
 padding-right: 20px;">If you lost your BTC or ETH, I will help you to reco=
ver your funds. I will charge 10% after your recovery. Whatsapp me at=C2=A0=
<a value=3D"+16469143655" target=3D"_blank" rel=3D"nofollow" style=3D"color=
: rgb(26, 115, 232);">+1-646-914-3655</a><div style=3D"color: rgb(80, 0, 80=
);"></div></div><div style=3D"padding: 16px 0px;"></div></div></div><div><d=
iv></div></div></div></span></div></div></div></span></span><div></div></di=
v><div style=3D"line-height: 1.5; text-size-adjust: 100%; tab-size: 4; font=
-family: ui-sans-serif, system-ui, sans-serif, &quot;Apple Color Emoji&quot=
;, &quot;Segoe UI Emoji&quot;, &quot;Segoe UI Symbol&quot;, &quot;Noto Colo=
r Emoji&quot;; font-feature-settings: normal; font-variation-settings: norm=
al; pointer-events: auto;"><div style=3D"box-sizing: border-box; border-wid=
th: 0px; border-style: solid; border-color: rgb(229, 231, 235); margin: 0px=
; padding: 0px;"><div lang=3D"en" style=3D"box-sizing: border-box; border-w=
idth: 0px; border-style: solid; border-color: rgb(229, 231, 235); margin: 0=
px; padding: 0px; font-family: -apple-system, BlinkMacSystemFont, &quot;Seg=
oe UI&quot;, Helvetica, Arial, sans-serif, &quot;Apple Color Emoji&quot;, &=
quot;Segoe UI Emoji&quot;; font-variation-settings: normal;"><div style=3D"=
box-sizing: border-box; border-width: 0px; border-style: solid; border-colo=
r: rgb(229, 231, 235); margin: 0px; padding: 0px; position: absolute; left:=
 0px; top: 0px; z-index: 2147483647;"><br /></div></div></div></div><br /><=
div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">On Friday,=
 January 23, 2026 at 1:44:13=E2=80=AFPM UTC+5 Peter Zijlstra wrote:<br/></d=
iv><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-l=
eft: 1px solid rgb(204, 204, 204); padding-left: 1ex;">On Thu, Jan 22, 2026=
 at 07:30:42AM +0100, Christoph Hellwig wrote:
<br>
<br>&gt; That&#39;s better.  What would be even better for everyone would b=
e:
<br>&gt;=20
<br>&gt; 	mutex_prepare(&amp;obj-&gt;mutex); /* acquire, but with a nice na=
me */
<br>&gt; 	obj-&gt;data =3D FOO;
<br>&gt; 	mutex_init_prepared(&amp;obj-&gt;mutex); /* release, barrier, act=
ual init */
<br>&gt;=20
<br>&gt; 	mutex_lock(&amp;obj-&gt;mutex); /* IFF needed only */
<br>&gt;=20
<br>
<br>This is cannot work. There is no such thing is a release-barrier.
<br>Furthermore, store-release, load-acquire needs an address dependency to
<br>work.
<br>
<br>When publishing an object, which is what we&#39;re talking about, we ha=
ve
<br>two common patterns:
<br>
<br> 1) a locked data-structure
<br>
<br> 2) RCU
<br>
<br>
<br>The way 1) works is:
<br>
<br>	Publish				Use
<br>
<br>	lock(&amp;structure_lock);
<br>	insert(&amp;structure, obj);
<br>	unlock(&amp;structure_lock);
<br>
<br>					lock(&amp;structure_lock)
<br>					obj =3D find(&amp;structure, key);
<br>					...
<br>					unlock(&amp;structure_lock);
<br>
<br>And here the Publish-unlock is a release which pairs with the Use-lock&=
#39;s
<br>acquire and guarantees that Use sees both &#39;structure&#39; in a cohe=
rent
<br>state and obj as it was at the time of insertion. IOW we have
<br>release-acquire through the &amp;structure_lock pointer.
<br>
<br>The way 2) works is:
<br>
<br>	Publish				Use
<br>
<br>	lock(&amp;structure_lock);
<br>	insert(&amp;structure, obj)
<br>	   rcu_assign_pointer(ptr, obj);
<br>	unlock(&amp;structure_lock);
<br>	  =09
<br>					rcu_read_lock();
<br>					obj =3D find_rcu(&amp;structure, key);
<br>					...
<br>					rcu_read_unlock();
<br>
<br>
<br>And here rcu_assign_pointer() is a store-release that pairs with an
<br>rcu_dereference() inside find_rcu() on the same pointer.
<br>
<br>There is no alternative way to order things, there must be a
<br>release-acquire through a common address.
<br>
<br>In both cases it is imperative the obj is fully (or full enough)
<br>initialized before publication, because the consumer is only guaranteed
<br>to see the state of the object it was in at publish time.
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/18d5679b-a386-4a0c-bccc-89e3f478f037n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/18d5679b-a386-4a0c-bccc-89e3f478f037n%40googlegroups.com</a>.<br />

------=_Part_526639_1828443150.1769396130422--

------=_Part_526638_1050013267.1769396130422--
